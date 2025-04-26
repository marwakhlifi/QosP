from flask import render_template, request, jsonify, redirect, url_for
from . import nslookup_bp
import dns.resolver
import dns.exception
import socket

@nslookup_bp.route('/other', methods=['GET'])
def other_page():
    """Render the nslookup tool page"""
    return render_template('other.html')

@nslookup_bp.route('/nslookup', methods=['GET'])
def nslookup_page():
    """Render the nslookup tool page"""
    return render_template('nslookup.html')

@nslookup_bp.route('/api/nslookup', methods=['POST'])
def perform_nslookup():
    data = request.get_json()
    domain = data.get('domain')
    record_type = data.get('type', 'A')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    try:
        domain = domain.strip()
        if not domain.startswith(('http://', 'https://')):
            domain = 'http://' + domain
        
        domain = domain.split('//')[-1].split('/')[0].split('?')[0]
        
        results = {
            'domain': domain,
            'type': record_type,
            'records': [],
            'error': None
        }
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                record = {
                    'ttl': answers.rrset.ttl,  
                    'value': str(rdata)
                }
                results['records'].append(record)
                
        except dns.resolver.NoAnswer:
            results['error'] = f'No {record_type} records found for {domain}'
        except dns.resolver.NXDOMAIN:
            results['error'] = f'Domain {domain} does not exist'
        except Exception as e:
            results['error'] = f'DNS query failed: {str(e)}'

        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@nslookup_bp.route('/network-tools')
def network_tools_dashboard():
    """Render the network tools dashboard"""
    return render_template('network.html')
