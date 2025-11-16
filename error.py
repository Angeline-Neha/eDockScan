
import pandas as pd
df = pd.read_csv('data/merged_docker_features.csv')

# Find images where CVEs should matter more
print("Images with HIGH CVEs but labeled SAFE (suspicious):")
suspicious_safe = df[(df['known_cves'] >= 30) & (df['label'] == 0)]
print(suspicious_safe[['known_cves', 'image_age_days', 'outdated_base', 'label']])

print("\nImages with LOW CVEs but labeled RISKY (suspicious):")
suspicious_risky = df[(df['known_cves'] < 10) & (df['label'] == 1)]
print(suspicious_risky[['known_cves', 'image_age_days', 'outdated_base', 'label']])

# Check feature correlations
print("\nFeature correlation with label:")
print(df.corr()['label'].sort_values(ascending=False))