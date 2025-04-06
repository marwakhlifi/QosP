from flask import Blueprint, request, render_template, current_app, jsonify
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import subprocess
from app.extensions import mongo
import os
import logging
import threading
import re
import queue
import smtplib
import matplotlib
matplotlib.use('Agg')  # Use Agg backend for non-GUI rendering
import tempfile

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import matplotlib.pyplot as plt  # Importing the plotting library

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()
from . import bp

# Queue for iPerf results
iperf_result_queue = queue.Queue()

def run_iperf_command(cmd):
    """Run iPerf command and return output"""
    try:
        # Run the iPerf command directly using subprocess.run
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=60)
        out = result.stdout.decode().strip()
        err = result.stderr.decode().strip()
        
        if err:
            return f"Error running iPerf: {err}"
        return out
    except Exception as e:
        return f"Error running iPerf: {str(e)}"

def parse_iperf_output(output):
    """Parse iPerf output to extract relevant metrics"""
    pattern = re.compile(
        r'\[\s*\d+\]\s+(\d+\.\d+-\d+\.\d+)\s+sec\s+([\d.]+)\s+(MBytes|KBytes|GBytes)\s+([\d.]+)\s+(Mbits/sec|Kbits/sec|Gbits/sec)'
    )
    intervals = []
    bandwidths = []

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            interval = match.group(1)
            bandwidth = float(match.group(4))
            unit = match.group(5)
            if unit == "Gbits/sec":
                bandwidth *= 1000
            elif unit == "Kbits/sec":
                bandwidth /= 1000
            intervals.append(interval)
            bandwidths.append(bandwidth)

    return {
        "intervals": intervals,
        "bandwidths": bandwidths,
        "raw_output": output
    }

def plot_bandwidth_graph(bandwidths, intervals, job_id):
    """Plot bandwidth graph from parsed iPerf results"""
    try:
        # Create a temporary directory if it doesn't exist
        temp_dir = os.path.join(tempfile.gettempdir(), 'iperf_graphs')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        # Plot bandwidth over time
        plt.figure(figsize=(10, 6))
        plt.plot(intervals, bandwidths, marker='o', linestyle='-', color='b')
        plt.xlabel('Interval (seconds)')
        plt.ylabel('Bandwidth (Mbps)')
        plt.title(f"iPerf Test Bandwidth Results for Job {job_id}")
        plt.grid(True)
        plt.tight_layout()
        
        # Save the plot as an image
        plot_filename = f"{job_id}_bandwidth_plot.png"
        plot_path = os.path.join(temp_dir, plot_filename)
        plt.savefig(plot_path)
        plt.close()  # Close the plot to avoid memory issues
        return plot_path
    except Exception as e:
        current_app.logger.error(f"Error generating graph: {str(e)}")
        return None

def execute_iperf_test(job_id, server_ip, client_ips, port, dscp, protocol, duration, data_size, unit):
    """Execute iPerf test for all client IPs"""
    try:
        current_app.logger.info(f"Starting iPerf test for job {job_id}")
        results = []
        
        # Path to iPerf executable (adjust as needed)
        iperf_path = current_app.config.get('IPERF_PATH', r'C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe')
        
        for ip in client_ips:
            cmd = [iperf_path, '-c', server_ip, '-p', str(port), '-S', str(dscp)]            

            if protocol.upper() == 'UDP':
                cmd.append('-u')
                cmd.extend(['-b', '100M'])  # Default bandwidth for UDP
            if duration:
                cmd.extend(['-t', str(duration)])
            if data_size:
                size = f"{data_size}{unit[0]}"  # Take first letter (MB -> M, GB -> G)
                cmd.extend(['-n', size])
            
            current_app.logger.info(f"Executing: {' '.join(cmd)}")
            
            result_text = run_iperf_command(cmd)
            current_app.logger.info(f"Results for {ip}:\n{result_text}")
            
            # Parse the output
            parsed_results = parse_iperf_output(result_text)
            results.append({
                "client_ip": ip,
                "raw_output": result_text,
                "metrics": parsed_results
            })

        # Generate the graph for bandwidth
        intervals = results[0]['metrics']['intervals']
        bandwidths = results[0]['metrics']['bandwidths']
        graph_path = plot_bandwidth_graph(bandwidths, intervals, job_id)

        # Update DB with results and graph path
        mongo.db.iperf_jobs.update_one(
            {'job_id': job_id},
            {'$set': {
                'status': 'completed',
                'results': results,
                'graph_path': graph_path,
                'completion_time': datetime.now()
            }}
        )
        
        # Send email to the user with the test results
        user_email = mongo.db.iperf_jobs.find_one({'job_id': job_id})['email']  # Get user's email from DB
        subject = f"iPerf Test Results for Job {job_id}"
        body = f"Test results for iPerf test job {job_id}:\n\n"
        for result in results:
            body += f"Client IP: {result['client_ip']}\n"
            body += f"Raw Output:\n{result['raw_output']}\n\n"

        send_email(subject, body, user_email, graph_path)

        return True, results
        
    except Exception as e:
        current_app.logger.error(f"Error in execute_iperf_test: {str(e)}")
        mongo.db.iperf_jobs.update_one(
            {'job_id': job_id},
            {'$set': {'status': 'failed', 'error': str(e)}}
        )
        return False, str(e)

def send_email(subject, body, to_email, image_path=None):
    """Send email with test results and optional image attachment"""
    try:
        # Sender and receiver email addresses
        sender_email = "maroukhlifi15@gmail.com"
        receiver_email = to_email

        # Set up the MIME
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # Attach the body with the msg
        msg.attach(MIMEText(body, 'plain'))

        # Attach the image if provided
        if image_path and os.path.exists(image_path):
            with open(image_path, 'rb') as img_file:
                img = MIMEImage(img_file.read())
                img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(image_path))
                msg.attach(img)

        # Set up the server (Gmail SMTP server)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Enable security
        server.login(sender_email, 'zjekskhpzzfneqwz')  # App password

        # Send email
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()

        logging.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")

@bp.route('/tempo')
def tempo():
    """Ensure the correct template is being rendered"""
    return render_template('tempo.html')

@bp.route('/schedule-test', methods=['GET', 'POST'])
def schedule_test():
    if request.method == 'POST':
        try:
            data = request.form
            current_app.logger.info(f"Received form data: {data}")
            
            # Required fields
            test_date = data.get('testDate')
            test_time = data.get('testTime')
            user_email = data.get('email')
            server_ip = data.get('serverIp')
            num_clients = int(data.get('numClients'))
            port = data.get('port')
            dscp = data.get('dscp')
            protocol = data.get('protocol')
            
            # Optional fields
            duration = data.get('testDuration') if 'testDurationCheckbox' in data else None
            data_size = data.get('dataSize') if 'dataSizeCheckbox' in data else None
            unit = data.get('dataUnit') if 'dataSizeCheckbox' in data else 'MB'

            client_ips = [data.get(f'clientIp{i+1}') for i in range(num_clients)]
            
            # Validate required fields
            if not all([test_date, test_time, server_ip, port, dscp, protocol]):
                return jsonify({'error': 'Missing required fields'}), 400

            scheduled_datetime = datetime.strptime(f"{test_date} {test_time}", "%Y-%m-%d %H:%M")
            job_id = f"iperf_{scheduled_datetime.timestamp()}_{server_ip}"

            # Save to DB
            mongo.db.iperf_jobs.insert_one({
                'job_id': job_id,
                'email': user_email,
                'server_ip': server_ip,
                'client_ips': client_ips,
                'port': port,
                'dscp': dscp,
                'protocol': protocol,
                'duration': duration,
                'data_size': data_size,
                'unit': unit,
                'scheduled_time': scheduled_datetime,
                'status': 'scheduled',
                'created_at': datetime.now()
            })

            # Get the actual app object (not the proxy)
            app = current_app._get_current_object()
            
            # Add job to scheduler with the app context
            scheduler.add_job(
                func=execute_iperf_test_wrapper,
                trigger='date',
                run_date=scheduled_datetime,
                args=[app, job_id, server_ip, client_ips, port, dscp, protocol, duration, data_size, unit],
                id=job_id
            )

            return jsonify({
                'message': f"iPerf test scheduled for {scheduled_datetime.strftime('%Y-%m-%d %H:%M')}",
                'job_id': job_id,
                'scheduled_time': scheduled_datetime.isoformat()
            })
            
        except Exception as e:
            current_app.logger.error(f"Error scheduling test: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    return render_template('tempo.html')

def execute_iperf_test_wrapper(app, job_id, server_ip, client_ips, port, dscp, protocol, duration, data_size, unit):
    """Wrapper function that establishes app context"""
    with app.app_context():
        success, results = execute_iperf_test(job_id, server_ip, client_ips, port, dscp, protocol, duration, data_size, unit)
        if success:
            current_app.logger.info(f"iPerf test completed successfully for job {job_id}")
        else:
            current_app.logger.error(f"iPerf test failed for job {job_id}: {results}")
            