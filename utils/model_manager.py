import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Standard features expected by the model matching CICIDS2017 & Scapy Extractor
FEATURE_KEYS = [
    'flow_duration',
    'total_fwd_pkts',
    'total_bwd_pkts',
    'total_fwd_bytes',
    'total_bwd_bytes',
    'fwd_pkt_len_max',
    'fwd_pkt_len_min',
    'fwd_pkt_len_mean',
    'bwd_pkt_len_max',
    'bwd_pkt_len_min',
    'bwd_pkt_len_mean',
    'flow_bytes_s',
    'flow_pkts_s',
    'fwd_header_len',
    'bwd_header_len',
    'syn_flag_cnt',
    'rst_flag_cnt',
    'psh_flag_cnt',
    'ack_flag_cnt',
    'urg_flag_cnt',
    'ece_flag_cnt',
    'fin_flag_cnt',
    'protocol'
]

# Mapping of labels to integer codes and friendly names
LABEL_MAP = {
    0: 'BENIGN',
    1: 'DoS',
    2: 'DDoS',
    3: 'PortScan',
    4: 'Botnet',
    5: 'Web Attack'
}

class ModelManager:
    def __init__(self, model_dir='models'):
        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, 'ids_model.joblib')
        self.legacy_dt_path = os.path.join(model_dir, 'decision_tree_model.joblib')
        self.scaler_path = os.path.join(model_dir, 'scaler.joblib')
        self.model = None
        self.scaler = None
        self._load_model()

    def _load_model(self):
        """Loads trained Decision Tree model and scaler from disk."""
        try:
            target_model_path = self.model_path if os.path.exists(self.model_path) else self.legacy_dt_path
            if os.path.exists(target_model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(target_model_path)
                self.scaler = joblib.load(self.scaler_path)
                model_name = type(self.model).__name__
                print(f"ML Model ({model_name}) and Scaler loaded successfully.")
            else:
                print("No pre-trained model found. Initializing with rule heuristics fallback.")
        except Exception as e:
            print(f"Error loading model: {e}. Falling back to rule heuristics.")

    def evaluate_heuristics(self, flow_data):
        """Rule heuristics analyzer for network flow characteristics."""
        duration = flow_data.get('flow_duration', 1)
        total_fwd_pkts = flow_data.get('total_fwd_pkts', 0)
        total_bwd_pkts = flow_data.get('total_bwd_pkts', 0)
        total_fwd_bytes = flow_data.get('total_fwd_bytes', 0)
        syn_cnt = flow_data.get('syn_flag_cnt', 0)
        rst_cnt = flow_data.get('rst_flag_cnt', 0)
        ack_cnt = flow_data.get('ack_flag_cnt', 0)
        flow_bytes_s = flow_data.get('flow_bytes_s', 0)
        flow_pkts_s = flow_data.get('flow_pkts_s', 0)
        
        if rst_cnt >= 5 or (total_fwd_pkts > 15 and syn_cnt > 5 and ack_cnt == 0):
            return 'PortScan', 72.0 + min(rst_cnt * 1.5, 18.0)
        elif (flow_pkts_s > 1000 and total_fwd_pkts > 40) or flow_bytes_s > 500000:
            return 'DDoS', 88.0 + min(flow_pkts_s / 500.0, 9.5)
        elif syn_cnt > 50 and duration < 2.0:
            return 'DoS', 80.0 + min(syn_cnt / 5.0, 15.0)
        elif flow_bytes_s > 5000000:
            return 'DoS', 76.0 + min((flow_bytes_s - 5000000) / 1000000.0, 14.0)
        elif total_fwd_bytes > 0 and total_fwd_pkts > 30 and flow_data.get('protocol', 6) == 6 and (flow_data.get('dport', 80) in [80, 443, 8080]):
            return 'Web Attack', 74.0 + min(total_fwd_pkts / 5.0, 15.0)
        else:
            return 'BENIGN', min((syn_cnt + rst_cnt) * 2.0, 15.0)

    def evaluate_heuristics_full(self, flow_data):
        label, score = self.evaluate_heuristics(flow_data)
        final_score = float(np.clip(score, 4.0, 98.5))
        final_score = round(final_score, 1)

        severity = 'Low'
        if final_score >= 85:
            severity = 'Critical'
        elif final_score >= 70:
            severity = 'High'
        elif final_score >= 40:
            severity = 'Medium'

        return label, final_score, severity

    def predict(self, flow):
        """
        Hybrid prediction engine combining the Decision Tree Classifier (trained on CICIDS2017)
        with Rule Heuristics validation.
        """
        heuristic_label, heuristic_score = self.evaluate_heuristics(flow)

        if self.model is None or self.scaler is None:
            return self.evaluate_heuristics_full(flow)

        try:
            vector_dict = {k: [float(flow.get(k, 0))] for k in FEATURE_KEYS}
            vector = pd.DataFrame(vector_dict)
            scaled_vector = self.scaler.transform(vector)
            
            dt_class = int(self.model.predict(scaled_vector)[0])
            dt_label = LABEL_MAP.get(dt_class, 'BENIGN')
            
            z_norm = float(np.linalg.norm(scaled_vector[0]))
            
            if hasattr(self.model, "predict_proba"):
                proba = self.model.predict_proba(scaled_vector)[0]
                dt_confidence = float(proba[dt_class]) if dt_class < len(proba) else 0.90
            else:
                dt_confidence = 0.90
                
            flow_pkts_s = float(flow.get('flow_pkts_s', 0))
            syn_cnt = float(flow.get('syn_flag_cnt', 0))
            total_fwd_pkts = float(flow.get('total_fwd_pkts', 0))
            
            # Refine DoS vs DDoS based on packet transmission rate and volume
            if dt_label in ['DoS', 'DDoS'] or heuristic_label in ['DoS', 'DDoS']:
                if flow_pkts_s > 1000 or (syn_cnt > 200 and total_fwd_pkts > 100):
                    final_label = 'DDoS'
                else:
                    final_label = 'DoS'
            elif dt_label != 'BENIGN':
                final_label = dt_label
            elif heuristic_label != 'BENIGN':
                final_label = heuristic_label
            else:
                final_label = 'BENIGN'

            # Add flow fingerprint variance (sport, dport, and src_ip byte hashing)
            sport = int(flow.get('sport', 0))
            dport = int(flow.get('dport', 0))
            ip_str = str(flow.get('src_ip', ''))
            ip_num = sum(int(b) for b in ip_str.replace('.', '') if b.isdigit())
            flow_var = ((sport * 3 + dport * 7 + ip_num * 5) % 17) * 0.45 if (sport or dport or ip_num) else 0.0

            if final_label == 'BENIGN':
                final_score = 5.0 + min(z_norm * 2.0, 18.0) + flow_var
            else:
                base_risk = {
                    'PortScan': 72.0,
                    'Web Attack': 74.0,
                    'DoS': 80.0,
                    'Botnet': 82.0,
                    'DDoS': 86.0
                }.get(final_label, 78.0)
                dt_risk = base_risk + (dt_confidence * 6.0) + min(z_norm * 0.8, 4.0) + flow_var
                final_score = dt_risk

            final_score = float(np.clip(final_score, 4.0, 98.2))
            final_score = round(final_score, 1)

            severity = 'Low'
            if final_score >= 85:
                severity = 'Critical'
            elif final_score >= 70:
                severity = 'High'
            elif final_score >= 40:
                severity = 'Medium'

            return final_label, final_score, severity
            
        except Exception as e:
            print(f"Error during ML prediction: {e}. Using rule heuristics fallback.")
            return self.evaluate_heuristics_full(flow)

    def train(self, df, algorithm='decision_tree'):
        """
        Trains and evaluates selected Decision Tree / ML algorithm on CICIDS2017 dataset
        with 80/20 train-test split.
        """
        os.makedirs(self.model_dir, exist_ok=True)
        df.columns = df.columns.str.strip().str.lower()
        
        missing = [col for col in FEATURE_KEYS if col not in df.columns]
        if missing:
            raise ValueError(f"Missing required training features in dataset: {missing}")
            
        label_col = None
        for col in ['label', 'class', 'attack']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            raise ValueError("Dataset must contain a target column named 'label' or 'class'.")
            
        def map_label(x):
            x_str = str(x).strip().lower()
            if 'benign' in x_str:
                return 0
            elif 'ddos' in x_str:
                return 2
            elif 'dos' in x_str or 'heartbleed' in x_str:
                return 1
            elif 'portscan' in x_str or 'port scan' in x_str:
                return 3
            elif 'botnet' in x_str or 'bot' in x_str:
                return 4
            elif 'web' in x_str or 'brute' in x_str or 'xss' in x_str or 'sql' in x_str or 'patator' in x_str:
                return 5
            else:
                return 0
                
        y = df[label_col].apply(map_label).values
        X = df[FEATURE_KEYS].copy()
        
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        # 80/20 Train-Test Split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        algo = algorithm.lower()
        if algo == 'knn':
            model = KNeighborsClassifier(n_neighbors=5)
        elif algo == 'random_forest':
            model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
        elif algo == 'adaboost':
            model = AdaBoostClassifier(n_estimators=50, random_state=42)
        else:
            model = DecisionTreeClassifier(max_depth=12, random_state=42)
            
        model.fit(X_train_scaled, y_train)
        
        t0 = time.time()
        preds = model.predict(X_test_scaled)
        inference_time_ms = (time.time() - t0) * 1000.0 / max(len(X_test), 1)
        
        acc = accuracy_score(y_test, preds)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, preds, average='weighted', zero_division=0)
        
        joblib.dump(model, self.model_path)
        joblib.dump(model, self.legacy_dt_path)
        joblib.dump(scaler, self.scaler_path)
        
        self.model = model
        self.scaler = scaler
        
        metrics = {
            'algorithm': type(model).__name__,
            'accuracy': float(acc),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'inference_time_ms_per_sample': float(inference_time_ms)
        }
        return metrics
