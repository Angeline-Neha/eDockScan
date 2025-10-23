# ============================================================
# E-COMMERCE CONTAINER SECURITY AUDITOR - COLAB IMPLEMENTATION
# Storage-Efficient Feature Extraction Without Full Images
# ============================================================

# PART 1: SETUP AND INSTALLATION
# ============================================================

# For optional live extraction (only if you want to demo)
# !apt-get install -y docker.io
# !systemctl start docker

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import xgboost as xgb
import shap
import matplotlib.pyplot as plt
import seaborn as sns
import re
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# PART 2: DATASET GENERATION (PRE-EXTRACTED FEATURES)
# ============================================================

def generate_complete_dataset():
    """
    Generate 300 Docker image feature vectors without pulling images.
    This creates the EXACT dataset your model needs for training.
    """
    
    data = []
    
    # -----------------------------------------------------------
    # SAFE IMAGES (200 total)
    # -----------------------------------------------------------
    
    # Official base images - nginx variants
    safe_nginx = [
        {'name': 'nginx:latest', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0, 
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 1, 
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 30, 'label': 0},
        {'name': 'nginx:1.21', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 2,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 180, 'label': 0},
        {'name': 'nginx:alpine', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 0,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 45, 'label': 0},
    ]
    
    # Python variants
    safe_python = [
        {'name': 'python:3.11', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 1, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 0,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 60, 'label': 0},
        {'name': 'python:3.10-slim', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 1,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 120, 'label': 0},
    ]
    
    # Node variants
    safe_node = [
        {'name': 'node:18', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 1, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 1,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 90, 'label': 0},
        {'name': 'node:16-alpine', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 2,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 200, 'label': 0},
    ]
    
    # Ubuntu/Debian variants
    safe_ubuntu = [
        {'name': 'ubuntu:22.04', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 1, 'known_cves': 3,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 150, 'label': 0},
        {'name': 'ubuntu:20.04', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 1, 'known_cves': 5,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 400, 'label': 0},
    ]
    
    # Database images
    safe_databases = [
        {'name': 'postgres:15', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 1,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 80, 'label': 0},
        {'name': 'mysql:8.0', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 2,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 100, 'label': 0},
        {'name': 'redis:7', 'cryptominer_binary': 0, 'mining_pools': 0, 'hardcoded_secrets': 0,
         'external_calls': 0, 'ssh_backdoor': 0, 'runs_as_root': 0, 'known_cves': 0,
         'outdated_base': 0, 'typosquatting_score': 0.0, 'image_age_days': 70, 'label': 0},
    ]
    
    # Combine safe base templates
    safe_templates = safe_nginx + safe_python + safe_node + safe_ubuntu + safe_databases
    
    # Replicate with variations to reach 200 safe images
    for i in range(200):
        template = safe_templates[i % len(safe_templates)].copy()
        # Add minor variations
        template['name'] = f"{template['name']}_variant_{i}"
        template['known_cves'] = np.random.randint(0, 4)
        template['image_age_days'] = np.random.randint(10, 300)
        template['external_calls'] = np.random.randint(0, 2)
        data.append(template)
    
    # -----------------------------------------------------------
    # RISKY IMAGES (100 total)
    # -----------------------------------------------------------
    
    # 1. CRYPTOMINER IMAGES (25)
    for i in range(25):
        data.append({
            'name': f'ubuntu_cryptominer_{i}',
            'cryptominer_binary': 1,  # Contains xmrig/cgminer
            'mining_pools': np.random.randint(1, 4),  # 1-3 pool references
            'hardcoded_secrets': np.random.randint(0, 2),
            'external_calls': np.random.randint(2, 5),  # Download miner + connect pool
            'ssh_backdoor': 0,
            'runs_as_root': 1,  # Miners need privileges
            'known_cves': np.random.randint(0, 3),
            'outdated_base': np.random.randint(0, 2),
            'typosquatting_score': np.random.uniform(0.3, 0.8),
            'image_age_days': np.random.randint(1, 30),  # Recently created
            'label': 1
        })
    
    # 2. SECRET STEALER IMAGES (25)
    for i in range(25):
        data.append({
            'name': f'python_secrets_{i}',
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'hardcoded_secrets': np.random.randint(2, 5),  # Multiple secrets
            'external_calls': np.random.randint(1, 4),  # Exfiltration attempts
            'ssh_backdoor': 0,
            'runs_as_root': np.random.randint(0, 2),
            'known_cves': np.random.randint(1, 5),
            'outdated_base': np.random.randint(0, 2),
            'typosquatting_score': np.random.uniform(0.4, 0.9),
            'image_age_days': np.random.randint(1, 60),
            'label': 1
        })
    
    # 3. SSH BACKDOOR IMAGES (20)
    for i in range(20):
        data.append({
            'name': f'ubuntu_backdoor_{i}',
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'hardcoded_secrets': np.random.randint(1, 3),  # Attacker credentials
            'external_calls': np.random.randint(1, 3),
            'ssh_backdoor': 1,  # openssh-server installed
            'runs_as_root': 1,
            'known_cves': np.random.randint(2, 8),
            'outdated_base': np.random.randint(0, 2),
            'typosquatting_score': np.random.uniform(0.5, 0.95),
            'image_age_days': np.random.randint(1, 45),
            'label': 1
        })
    
    # 4. PRIVILEGE ESCALATION IMAGES (15)
    for i in range(15):
        data.append({
            'name': f'debian_privesc_{i}',
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'hardcoded_secrets': np.random.randint(0, 2),
            'external_calls': np.random.randint(1, 3),
            'ssh_backdoor': np.random.randint(0, 2),
            'runs_as_root': 1,  # Always root
            'known_cves': np.random.randint(5, 15),  # Many vulnerabilities
            'outdated_base': 1,  # Old base image
            'typosquatting_score': np.random.uniform(0.6, 1.0),
            'image_age_days': np.random.randint(1, 90),
            'label': 1
        })
    
    # 5. VULNERABLE IMAGES (15) - Vulhub-style
    for i in range(15):
        data.append({
            'name': f'vulhub_vulnerable_{i}',
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'hardcoded_secrets': np.random.randint(0, 2),
            'external_calls': np.random.randint(0, 2),
            'ssh_backdoor': 0,
            'runs_as_root': np.random.randint(0, 2),
            'known_cves': np.random.randint(8, 20),  # Many known CVEs
            'outdated_base': 1,  # Definitely outdated
            'typosquatting_score': np.random.uniform(0.2, 0.7),
            'image_age_days': np.random.randint(365, 1000),  # Very old
            'label': 1
        })
    
    return pd.DataFrame(data)

# ============================================================
# PART 3: GENERATE AND SAVE DATASET
# ============================================================

print("🔄 Generating complete dataset with 300 images...")
df = generate_complete_dataset()

# Save to CSV
df.to_csv('docker_security_features.csv', index=False)
print(f"✅ Dataset created: {df.shape[0]} images, {df.shape[1]-1} features")
print(f"\n📊 Class Distribution:")
print(df['label'].value_counts())
print(f"\n🔍 First 5 rows:")
print(df.head())

# ============================================================
# PART 4: EXPLORATORY DATA ANALYSIS
# ============================================================

def analyze_dataset(df):
    """Perform EDA on the dataset"""
    
    print("\n" + "="*60)
    print("📈 DATASET STATISTICS")
    print("="*60)
    
    # Basic stats
    print(f"\nTotal Images: {len(df)}")
    print(f"Safe Images: {len(df[df['label']==0])} ({len(df[df['label']==0])/len(df)*100:.1f}%)")
    print(f"Risky Images: {len(df[df['label']==1])} ({len(df[df['label']==1])/len(df)*100:.1f}%)")
    
    # Feature statistics
    print("\n🔢 Feature Statistics:")
    print(df.describe().round(2))
    
    # Correlation analysis
    print("\n🔗 Top Correlations with Label:")
    correlations = df.select_dtypes(include=[np.number]).corr()['label'].sort_values(ascending=False)

    print(correlations[1:6])  # Top 5 features
    
    # Visualizations
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Class distribution
    df['label'].value_counts().plot(kind='bar', ax=axes[0,0], color=['green', 'red'])
    axes[0,0].set_title('Class Distribution', fontsize=14, fontweight='bold')
    axes[0,0].set_xlabel('Label (0=Safe, 1=Risky)')
    axes[0,0].set_ylabel('Count')
    axes[0,0].set_xticklabels(['Safe', 'Risky'], rotation=0)
    
    # 2. Feature correlation heatmap
    feature_cols = ['cryptominer_binary', 'mining_pools', 'hardcoded_secrets', 
                    'external_calls', 'ssh_backdoor', 'runs_as_root', 
                    'known_cves', 'outdated_base']
    sns.heatmap(df[feature_cols + ['label']].corr(), annot=True, fmt='.2f', 
                cmap='RdYlGn_r', ax=axes[0,1], cbar_kws={'label': 'Correlation'})
    axes[0,1].set_title('Feature Correlation Matrix', fontsize=14, fontweight='bold')
    
    # 3. Key features distribution
    key_features = ['cryptominer_binary', 'hardcoded_secrets', 'ssh_backdoor', 'known_cves']
    df_plot = df[key_features + ['label']].melt(id_vars='label', var_name='Feature', value_name='Value')
    sns.boxplot(data=df_plot, x='Feature', y='Value', hue='label', ax=axes[1,0])
    axes[1,0].set_title('Key Feature Distribution by Label', fontsize=14, fontweight='bold')
    axes[1,0].set_xticklabels(axes[1,0].get_xticklabels(), rotation=45, ha='right')
    axes[1,0].legend(title='Label', labels=['Safe', 'Risky'])
    
    # 4. Risk indicators
    risk_counts = df[df['label']==1][['cryptominer_binary', 'mining_pools', 
                                       'hardcoded_secrets', 'ssh_backdoor']].sum()
    risk_counts.plot(kind='barh', ax=axes[1,1], color='crimson')
    axes[1,1].set_title('Risk Indicator Frequency (Risky Images)', fontsize=14, fontweight='bold')
    axes[1,1].set_xlabel('Count')
    
    plt.tight_layout()
    plt.savefig('dataset_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("\n✅ Analysis complete! Visualization saved as 'dataset_analysis.png'")

# Run EDA
analyze_dataset(df)

# ============================================================
# PART 5: TRAIN ML MODEL
# ============================================================

def train_model(df):
    """Train XGBoost classifier on the dataset"""
    
    print("\n" + "="*60)
    print("🤖 TRAINING ML MODEL")
    print("="*60)
    
    # Prepare features and labels
    feature_cols = ['cryptominer_binary', 'mining_pools', 'hardcoded_secrets',
                    'external_calls', 'ssh_backdoor', 'runs_as_root',
                    'known_cves', 'outdated_base', 'typosquatting_score', 'image_age_days']
    
    X = df[feature_cols]
    y = df['label']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n📊 Data Split:")
    print(f"  Training: {len(X_train)} images")
    print(f"  Testing: {len(X_test)} images")
    
    # Feature scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train XGBoost model
    print(f"\n⚙️ Training XGBoost Classifier...")
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=5,
        learning_rate=0.1,
        scale_pos_weight=len(y_train[y_train==0]) / len(y_train[y_train==1]),  # Handle imbalance
        random_state=42,
        eval_metric='logloss'
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Predictions
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    # Evaluation
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\n✅ Model Performance:")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1-Score:  {f1*100:.2f}%")
    
    print(f"\n📋 Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Risky']))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'Feature': feature_cols,
        'Importance': model.feature_importances_
    }).sort_values('Importance', ascending=False)
    
    print(f"\n🔍 Feature Importance:")
    print(feature_importance)
    
    # Visualization
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    
    # Feature importance plot
    feature_importance.plot(x='Feature', y='Importance', kind='barh', ax=axes[0], color='steelblue')
    axes[0].set_title('Feature Importance', fontsize=14, fontweight='bold')
    axes[0].set_xlabel('Importance Score')
    
    # Confusion matrix
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1],
                xticklabels=['Safe', 'Risky'], yticklabels=['Safe', 'Risky'])
    axes[1].set_title('Confusion Matrix', fontsize=14, fontweight='bold')
    axes[1].set_ylabel('True Label')
    axes[1].set_xlabel('Predicted Label')
    
    plt.tight_layout()
    plt.savefig('model_performance.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    return model, scaler, X_test_scaled, y_test, feature_cols

# Train the model
model, scaler, X_test_scaled, y_test, feature_cols = train_model(df)

# ============================================================
# PART 6: SHAP EXPLAINABILITY
# ============================================================

def explain_predictions(model, X_test_scaled, y_test, feature_cols, num_samples=5):
    """Generate SHAP explanations for predictions"""
    
    print("\n" + "="*60)
    print("🔍 SHAP EXPLAINABILITY ANALYSIS")
    print("="*60)
    
    # Create SHAP explainer
    print("\n⚙️ Computing SHAP values...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test_scaled)
    
    # Summary plot
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_values, X_test_scaled, feature_names=feature_cols, show=False)
    plt.title('SHAP Feature Importance Summary', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig('shap_summary.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    # Explain individual predictions
    print(f"\n📊 Explaining {num_samples} Sample Predictions:")
    print("-" * 60)
    
    for i in range(min(num_samples, len(X_test_scaled))):
        pred = model.predict(X_test_scaled[i:i+1])[0]
        pred_proba = model.predict_proba(X_test_scaled[i:i+1])[0]
        true_label = y_test.iloc[i]
        
        print(f"\n🔹 Sample {i+1}:")
        print(f"  True Label: {'RISKY' if true_label == 1 else 'SAFE'}")
        print(f"  Predicted:  {'RISKY' if pred == 1 else 'SAFE'}")
        print(f"  Confidence: {pred_proba[1]*100:.1f}% risky")
        
        # Top SHAP contributors
        sample_shap = shap_values[i]
        contributions = pd.DataFrame({
            'Feature': feature_cols,
            'SHAP_Value': sample_shap
        }).sort_values('SHAP_Value', key=abs, ascending=False)
        
        print(f"  Top Contributing Features:")
        for idx, row in contributions.head(3).iterrows():
            direction = "increases" if row['SHAP_Value'] > 0 else "decreases"
            print(f"    • {row['Feature']}: {direction} risk by {abs(row['SHAP_Value']):.3f}")
    
    print("\n✅ SHAP analysis complete!")
    
    return explainer, shap_values

# Run SHAP analysis
explainer, shap_values = explain_predictions(model, X_test_scaled, y_test, feature_cols)

# ============================================================
# PART 7: RISK SCORING SYSTEM
# ============================================================

def calculate_risk_score(model, scaler, features_dict):
    """
    Calculate comprehensive risk score (0-10) for a container image
    
    Args:
        model: Trained XGBoost model
        scaler: Fitted StandardScaler
        features_dict: Dictionary with 10 feature values
    
    Returns:
        dict with risk_score, prediction, probability, explanation
    """
    
    # Prepare input
    feature_order = ['cryptominer_binary', 'mining_pools', 'hardcoded_secrets',
                     'external_calls', 'ssh_backdoor', 'runs_as_root',
                     'known_cves', 'outdated_base', 'typosquatting_score', 'image_age_days']
    
    input_vector = np.array([[features_dict[f] for f in feature_order]])
    input_scaled = scaler.transform(input_vector)
    
    # Get prediction
    prediction = model.predict(input_scaled)[0]
    probability = model.predict_proba(input_scaled)[0][1]  # Probability of being risky
    
    # Calculate composite risk score (0-10)
    # Formula: (Model_Probability × 7) + (Feature_Severity × 2) + (CVE_Count × 1)
    
    model_component = probability * 7.0
    
    # Feature severity (normalized 0-1)
    feature_severity = (
        features_dict['cryptominer_binary'] * 0.3 +
        (features_dict['mining_pools'] / 5) * 0.25 +
        (features_dict['hardcoded_secrets'] / 5) * 0.2 +
        features_dict['ssh_backdoor'] * 0.15 +
        features_dict['runs_as_root'] * 0.1
    )
    feature_component = feature_severity * 2.0
    
    # CVE component (normalized 0-1)
    cve_severity = min(features_dict['known_cves'] / 20, 1.0)
    cve_component = cve_severity * 1.0
    
    risk_score = min(model_component + feature_component + cve_component, 10.0)
    
    # Risk level
    if risk_score < 2:
        risk_level = "✅ SAFE"
        color = "green"
    elif risk_score < 4:
        risk_level = "⚠️ LOW RISK"
        color = "yellow"
    elif risk_score < 7:
        risk_level = "⚠️⚠️ MEDIUM RISK"
        color = "orange"
    elif risk_score < 9:
        risk_level = "🔴 HIGH RISK"
        color = "red"
    else:
        risk_level = "🔴🔴 CRITICAL RISK"
        color = "darkred"
    
    # Generate explanation
    risk_factors = []
    if features_dict['cryptominer_binary'] == 1:
        risk_factors.append("Contains cryptominer binary")
    if features_dict['mining_pools'] > 0:
        risk_factors.append(f"References {features_dict['mining_pools']} mining pool(s)")
    if features_dict['hardcoded_secrets'] > 0:
        risk_factors.append(f"Contains {features_dict['hardcoded_secrets']} hardcoded secret(s)")
    if features_dict['ssh_backdoor'] == 1:
        risk_factors.append("SSH backdoor detected")
    if features_dict['runs_as_root'] == 1:
        risk_factors.append("Runs as root user")
    if features_dict['known_cves'] > 5:
        risk_factors.append(f"{features_dict['known_cves']} known vulnerabilities")
    
    explanation = " | ".join(risk_factors) if risk_factors else "No major risk factors detected"
    
    return {
        'risk_score': round(risk_score, 2),
        'risk_level': risk_level,
        'prediction': 'RISKY' if prediction == 1 else 'SAFE',
        'probability': round(probability * 100, 1),
        'explanation': explanation,
        'components': {
            'model_contribution': round(model_component, 2),
            'feature_contribution': round(feature_component, 2),
            'cve_contribution': round(cve_component, 2)
        }
    }

# ============================================================
# PART 8: DEMONSTRATION - ANALYZE SAMPLE IMAGES
# ============================================================

print("\n" + "="*60)
print("🧪 ANALYZING SAMPLE DOCKER IMAGES")
print("="*60)

# Test Case 1: Safe nginx image
safe_image = {
    'cryptominer_binary': 0,
    'mining_pools': 0,
    'hardcoded_secrets': 0,
    'external_calls': 0,
    'ssh_backdoor': 0,
    'runs_as_root': 0,
    'known_cves': 1,
    'outdated_base': 0,
    'typosquatting_score': 0.0,
    'image_age_days': 45
}

result1 = calculate_risk_score(model, scaler, safe_image)
print(f"\n🔹 Test Case 1: nginx:latest")
print(f"  Risk Score: {result1['risk_score']}/10")
print(f"  Risk Level: {result1['risk_level']}")
print(f"  Prediction: {result1['prediction']} ({result1['probability']}% confidence)")
print(f"  Explanation: {result1['explanation']}")

# Test Case 2: Cryptominer image
cryptominer_image = {
    'cryptominer_binary': 1,
    'mining_pools': 2,
    'hardcoded_secrets': 1,
    'external_calls': 3,
    'ssh_backdoor': 0,
    'runs_as_root': 1,
    'known_cves': 2,
    'outdated_base': 0,
    'typosquatting_score': 0.75,
    'image_age_days': 5
}

result2 = calculate_risk_score(model, scaler, cryptominer_image)
print(f"\n🔹 Test Case 2: ubuntu_cryptominer:latest")
print(f"  Risk Score: {result2['risk_score']}/10")
print(f"  Risk Level: {result2['risk_level']}")
print(f"  Prediction: {result2['prediction']} ({result2['probability']}% confidence)")
print(f"  Explanation: {result2['explanation']}")

# Test Case 3: SSH Backdoor
backdoor_image = {
    'cryptominer_binary': 0,
    'mining_pools': 0,
    'hardcoded_secrets': 2,
    'external_calls': 1,
    'ssh_backdoor': 1,
    'runs_as_root': 1,
    'known_cves': 5,
    'outdated_base': 1,
    'typosquatting_score': 0.9,
    'image_age_days': 10
}

result3 = calculate_risk_score(model, scaler, backdoor_image)
print(f"\n🔹 Test Case 3: debian_backdoor:v1")
print(f"  Risk Score: {result3['risk_score']}/10")
print(f"  Risk Level: {result3['risk_level']}")
print(f"  Prediction: {result3['prediction']} ({result3['probability']}% confidence)")
print(f"  Explanation: {result3['explanation']}")

# ============================================================
# PART 9: SAVE MODEL FOR PRODUCTION
# ============================================================

import pickle

# Save model and scaler
with open('xgboost_model.pkl', 'wb') as f:
    pickle.dump(model, f)

with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

with open('feature_columns.pkl', 'wb') as f:
    pickle.dump(feature_cols, f)

print("\n" + "="*60)
print("💾 MODEL SAVED")
print("="*60)
print("✅ xgboost_model.pkl")
print("✅ scaler.pkl")
print("✅ feature_columns.pkl")
print("✅ docker_security_features.csv")

print("\n🎉 Training Complete! Model ready for deployment.")