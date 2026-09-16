import os
import pandas as pd
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from utils.model_manager import ModelManager, FEATURE_KEYS
from utils.extractor import extract_flows

app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB upload limit

# Initialize Model Manager
model_manager = ModelManager()

def allowed_file(filename):
    if '.' not in filename:
        return filename.lower() in {'syslog', 'messages', 'secure'}
    ext = filename.rsplit('.', 1)[1].lower()
    if filename.lower().startswith('auth.log'):
        return True
    return ext in {'pcap', 'csv', 'log', 'txt'}

@app.route('/')
def index():
    """Renders the main dashboard template."""
    return render_template('index.html')

@app.route('/sw.js')
def service_worker():
    """Serves an empty service worker to resolve browser 404 updates for local development ports."""
    response = app.make_response("")
    response.headers['Content-Type'] = 'application/javascript'
    return response

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles PCAP, CSV or Log uploads, parses flows/logs, runs predictions/rules, and returns results."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported file format. Please upload .pcap, .csv, or syslog files.'}), 400
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    # Smart Upload Routing
    is_network = False
    is_system = False
    
    if file_ext == 'pcap':
        is_network = True
    elif file_ext == 'csv':
        try:
            df_peek = pd.read_csv(filepath, nrows=2)
            df_peek.columns = df_peek.columns.str.strip().str.lower()
            network_cols = {'protocol', 'flow duration', 'flow_duration', 'source ip', 'src_ip', 'destination ip', 'dst_ip'}
            if any(c in df_peek.columns for c in network_cols):
                is_network = True
            else:
                is_system = True
        except Exception:
            is_system = True
    else:
        is_system = True
        
    if is_system:
        from utils.syslog_parser import parse_system_log
        try:
            results = parse_system_log(filepath, filename)
            if not results:
                if os.path.exists(filepath):
                    os.remove(filepath)
                return jsonify({'error': 'No valid system log entries parsed from the file.'}), 400
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify(results)
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': f'Failed to parse system log: {str(e)}'}), 500
            
    flows_data = []
    try:
        if file_ext == 'pcap':
            # Extract flows from PCAP using Scapy
            flows_data = extract_flows(filepath)
        elif file_ext == 'csv':
            # Load flows from CSV using Pandas
            df = pd.read_csv(filepath)
            
            # Clean columns: strip whitespaces and convert to lowercase
            df.columns = df.columns.str.strip().str.lower()
            
            # Mapping of common CICFlowMeter labels to standard keys
            rename_map = {
                'flow duration': 'flow_duration',
                'total fwd packets': 'total_fwd_pkts',
                'total backward packets': 'total_bwd_pkts',
                'total length of fwd packets': 'total_fwd_bytes',
                'total length of bwd packets': 'total_bwd_bytes',
                'fwd packet length max': 'fwd_pkt_len_max',
                'fwd_packet_length_max': 'fwd_pkt_len_max',
                'fwd packet length min': 'fwd_pkt_len_min',
                'fwd_packet_length_min': 'fwd_pkt_len_min',
                'fwd packet length mean': 'fwd_pkt_len_mean',
                'fwd_packet_length_mean': 'fwd_pkt_len_mean',
                'bwd packet length max': 'bwd_pkt_len_max',
                'bwd_packet_length_max': 'bwd_pkt_len_max',
                'bwd packet length min': 'bwd_pkt_len_min',
                'bwd_packet_length_min': 'bwd_pkt_len_min',
                'bwd packet length mean': 'bwd_pkt_len_mean',
                'bwd_packet_length_mean': 'bwd_pkt_len_mean',
                'flow bytes/s': 'flow_bytes_s',
                'flow_bytes_s': 'flow_bytes_s',
                'flow packets/s': 'flow_pkts_s',
                'flow_pkts_s': 'flow_pkts_s',
                'fwd header length': 'fwd_header_len',
                'bwd header length': 'bwd_header_len',
                'syn flag count': 'syn_flag_cnt',
                'syn_flag_cnt': 'syn_flag_cnt',
                'rst flag count': 'rst_flag_cnt',
                'rst_flag_cnt': 'rst_flag_cnt',
                'psh flag count': 'psh_flag_cnt',
                'psh_flag_cnt': 'psh_flag_cnt',
                'ack flag count': 'ack_flag_cnt',
                'ack_flag_cnt': 'ack_flag_cnt',
                'urg flag count': 'urg_flag_cnt',
                'urg_flag_cnt': 'urg_flag_cnt',
                'ece flag count': 'ece_flag_cnt',
                'ece_flag_cnt': 'ece_flag_cnt',
                'fin flag count': 'fin_flag_cnt',
                'fin_flag_cnt': 'fin_flag_cnt',
                'protocol': 'protocol'
            }
            df = df.rename(columns=rename_map)
            
            # Extract basic identifiers if present, else assign defaults
            src_ip_col = next((c for c in ['source ip', 'src ip', 'src_ip', 'source_ip'] if c in df.columns), None)
            dst_ip_col = next((c for c in ['destination ip', 'dst ip', 'dst_ip', 'destination_ip'] if c in df.columns), None)
            sport_col = next((c for c in ['source port', 'src port', 'sport', 'source_port'] if c in df.columns), None)
            dport_col = next((c for c in ['destination port', 'dst port', 'dport', 'destination_port'] if c in df.columns), None)
            proto_col = next((c for c in ['protocol', 'proto'] if c in df.columns), None)
            
            for index, row in df.iterrows():
                flow = {}
                # Set metadata
                flow['src_ip'] = str(row[src_ip_col]) if src_ip_col else 'N/A'
                flow['dst_ip'] = str(row[dst_ip_col]) if dst_ip_col else 'N/A'
                flow['sport'] = int(row[sport_col]) if sport_col and not pd.isna(row[sport_col]) else 0
                flow['dport'] = int(row[dport_col]) if dport_col and not pd.isna(row[dport_col]) else 0
                
                proto_val = int(row[proto_col]) if proto_col and not pd.isna(row[proto_col]) else 6
                flow['protocol'] = proto_val
                flow['protocol_name'] = 'TCP' if proto_val == 6 else ('UDP' if proto_val == 17 else 'Other')
                
                # Fetch ML features
                for key in FEATURE_KEYS:
                    if key in df.columns:
                        val = row[key]
                        # Handle NaNs or Infinities
                        if pd.isna(val) or val == float('inf') or val == float('-inf'):
                            flow[key] = 0.0
                        else:
                            flow[key] = float(val)
                    else:
                        flow[key] = 0.0
                        
                flows_data.append(flow)
                
    except Exception as e:
        print(f"Error processing upload: {e}")
        # Clean up file
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Failed to process file: {str(e)}'}), 500
        
    # Clean up file
    if os.path.exists(filepath):
        os.remove(filepath)
        
    if not flows_data:
        return jsonify({'error': 'No valid network flows found in the uploaded file.'}), 400
        
    # Run predictions & aggregate stats
    predictions = []
    total_flows = len(flows_data)
    anomalies_count = 0
    max_risk_score = 0.0
    total_risk_score = 0.0
    
    category_counts = {
        'BENIGN': 0,
        'DoS': 0,
        'DDoS': 0,
        'PortScan': 0,
        'Botnet': 0,
        'Web Attack': 0
    }
    
    for flow in flows_data:
        label, score, severity = model_manager.predict(flow)
        
        if label != 'BENIGN':
            anomalies_count += 1
            
        category_counts[label] = category_counts.get(label, 0) + 1
        max_risk_score = max(max_risk_score, score)
        total_risk_score += score
        
        # Keep essential data for table rendering to avoid heavy responses
        predictions.append({
            'src_ip': flow['src_ip'],
            'sport': flow['sport'],
            'dst_ip': flow['dst_ip'],
            'dport': flow['dport'],
            'protocol_name': flow['protocol_name'],
            'flow_duration': round(flow['flow_duration'], 2),
            'total_fwd_pkts': flow['total_fwd_pkts'],
            'total_bwd_pkts': flow['total_bwd_pkts'],
            'label': label,
            'risk_score': round(score, 2),
            'severity': severity
        })
        
    avg_risk_score = total_risk_score / total_flows if total_flows > 0 else 0.0
    
    # Calculate overall risk status
    overall_severity = 'Low'
    if max_risk_score >= 85:
        overall_severity = 'Critical'
    elif max_risk_score >= 70:
        overall_severity = 'High'
    elif max_risk_score >= 40:
        overall_severity = 'Medium'
        
    results = {
        'filename': filename,
        'total_flows': total_flows,
        'anomalies_found': anomalies_count,
        'max_risk_score': round(max_risk_score, 2),
        'avg_risk_score': round(avg_risk_score, 2),
        'overall_severity': overall_severity,
        'category_counts': category_counts,
        'flows': predictions
    }
    
    return jsonify(results)

@app.route('/train', methods=['POST'])
def train_model():
    """Allows uploading a new CSV dataset to retrain the Decision Tree model."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Training requires a CSV format dataset.'}), 400
        
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        df = pd.read_csv(filepath)
        metrics = model_manager.train(df)
        
        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)
            
        return jsonify({
            'message': 'Decision Tree model retrained successfully!',
            'metrics': metrics
        })
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Failed to train model: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
