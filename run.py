# run.py
import sys
import os
print("Current sys.path:", sys.path)
print("Current working directory:", os.getcwd())

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5100)