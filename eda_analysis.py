"""
Exploratory Data Analysis (EDA) for Phishing Website Detection
Includes: Correlation analysis, Performance metrics, Dataset distribution,
Top 15 important features, URL length distribution, and feature correlations
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Set style for better visualizations
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

# =====================================================================
# 1. Load and Explore Data
# =====================================================================
print("=" * 80)
print("PHISHING WEBSITE DETECTION - EXPLORATORY DATA ANALYSIS")
print("=" * 80)

# Load dataset
df = pd.read_csv('data/webpage_phishing_detection_dataset.csv')
print(f"\nDataset Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"\nFirst few rows:")
print(df.head())

# =====================================================================
# 2. Dataset Distribution Analysis
# =====================================================================
print("\n" + "=" * 80)
print("2. DATASET DISTRIBUTION")
print("=" * 80)

# Get target column (last column)
target_col = df.columns[-1]
print(f"\nTarget Column: {target_col}")

# Class distribution
class_dist = df[target_col].value_counts()
print(f"\nClass Distribution:")
print(class_dist)
print(f"\nClass Distribution (%):")
print(df[target_col].value_counts(normalize=True) * 100)

# Visualize class distribution
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Bar plot
class_dist.plot(kind='bar', ax=axes[0], color=['#FF6B6B', '#4ECDC4'])
axes[0].set_title('Class Distribution', fontsize=14, fontweight='bold')
axes[0].set_xlabel('Class')
axes[0].set_ylabel('Count')
axes[0].tick_params(axis='x', rotation=0)

# Pie chart
axes[1].pie(class_dist.values, labels=class_dist.index, autopct='%1.1f%%',
            colors=['#FF6B6B', '#4ECDC4'], startangle=90)
axes[1].set_title('Class Distribution (%)', fontsize=14, fontweight='bold')

plt.tight_layout()
plt.savefig('visualizations/dataset_distribution.png', dpi=300, bbox_inches='tight')
print("\n✓ Saved: visualizations/dataset_distribution.png")
plt.close()

# =====================================================================
# 3. Numerical Features Analysis
# =====================================================================
print("\n" + "=" * 80)
print("3. NUMERICAL FEATURES STATISTICS")
print("=" * 80)

# Get numerical columns (exclude URL and target)
numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
if target_col in numerical_cols:
    numerical_cols.remove(target_col)

print(f"\nNumber of Numerical Features: {len(numerical_cols)}")
print("\nStatistical Summary:")
print(df[numerical_cols].describe().round(3))

# Check for missing values
print(f"\nMissing Values:")
print(df[numerical_cols].isnull().sum())

# =====================================================================
# 4. URL Length Distribution by Class
# =====================================================================
print("\n" + "=" * 80)
print("4. URL LENGTH DISTRIBUTION BY CLASS")
print("=" * 80)

if 'length_url' in df.columns:
    print("\nURL Length Statistics:")
    print(df.groupby(target_col)['length_url'].describe().round(2))
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Distribution plot
    for idx, class_val in enumerate(df[target_col].unique()):
        ax = axes[idx // 2, idx % 2]
        data = df[df[target_col] == class_val]['length_url']
        ax.hist(data, bins=30, color=['#FF6B6B', '#4ECDC4'][idx], alpha=0.7, edgecolor='black')
        ax.set_title(f'URL Length Distribution - Class {class_val}', fontsize=12, fontweight='bold')
        ax.set_xlabel('URL Length')
        ax.set_ylabel('Frequency')
        ax.axvline(data.mean(), color='red', linestyle='--', linewidth=2, label=f'Mean: {data.mean():.2f}')
        ax.legend()
    
    # Box plot
    ax = axes[1, 1]
    df.boxplot(column='length_url', by=target_col, ax=ax)
    ax.set_title('URL Length Distribution (Box Plot)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Class')
    ax.set_ylabel('URL Length')
    plt.suptitle('')  # Remove the automatic title
    
    plt.tight_layout()
    plt.savefig('visualizations/url_length_distribution.png', dpi=300, bbox_inches='tight')
    print("\n✓ Saved: visualizations/url_length_distribution.png")
    plt.close()

# =====================================================================
# 5. Feature Importance (Top 15)
# =====================================================================
print("\n" + "=" * 80)
print("5. TOP 15 MOST IMPORTANT FEATURES")
print("=" * 80)

# Prepare data for model
X = df[numerical_cols].copy()
y = df[target_col].copy()

# Handle any NaN values
X = X.fillna(X.mean())

# Train a Random Forest to get feature importance
print("\nTraining Random Forest for feature importance...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_model.fit(X, y)

# Get feature importance
feature_importance = pd.DataFrame({
    'Feature': numerical_cols,
    'Importance': rf_model.feature_importances_
}).sort_values('Importance', ascending=False)

print("\nTop 15 Most Important Features:")
print(feature_importance.head(15).to_string(index=False))

# Visualize top 15 features
fig, ax = plt.subplots(figsize=(12, 8))
top_15 = feature_importance.head(15)
colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(top_15)))
bars = ax.barh(range(len(top_15)), top_15['Importance'].values, color=colors)
ax.set_yticks(range(len(top_15)))
ax.set_yticklabels(top_15['Feature'].values)
ax.set_xlabel('Importance Score', fontsize=12, fontweight='bold')
ax.set_title('Top 15 Most Important Features', fontsize=14, fontweight='bold')
ax.invert_yaxis()

# Add value labels on bars
for i, (idx, row) in enumerate(top_15.iterrows()):
    ax.text(row['Importance'], i, f" {row['Importance']:.4f}", va='center')

plt.tight_layout()
plt.savefig('visualizations/top_15_features.png', dpi=300, bbox_inches='tight')
print("\n✓ Saved: visualizations/top_15_features.png")
plt.close()

# =====================================================================
# 6. Correlation Matrix - Top 10 Features
# =====================================================================
print("\n" + "=" * 80)
print("6. FEATURE CORRELATION MATRIX (TOP 10 FEATURES)")
print("=" * 80)

top_10_features = feature_importance.head(10)['Feature'].tolist()
print(f"\nTop 10 Features: {top_10_features}")

# Create correlation matrix for top 10 features
correlation_matrix_top10 = df[top_10_features].corr()
print("\nCorrelation Matrix (Top 10 Features):")
print(correlation_matrix_top10.round(3))

# Visualize correlation heatmap
fig, ax = plt.subplots(figsize=(12, 10))
sns.heatmap(correlation_matrix_top10, annot=True, fmt='.2f', cmap='coolwarm', 
            center=0, square=True, linewidths=0.5, cbar_kws={"shrink": 0.8}, ax=ax)
ax.set_title('Feature Correlation Matrix - Top 10 Features', fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig('visualizations/correlation_matrix_top10.png', dpi=300, bbox_inches='tight')
print("\n✓ Saved: visualizations/correlation_matrix_top10.png")
plt.close()

# =====================================================================
# 7. Overall Correlation Analysis
# =====================================================================
print("\n" + "=" * 80)
print("7. OVERALL CORRELATION ANALYSIS - ALL FEATURES")
print("=" * 80)

# Create correlation matrix for all numerical features
correlation_matrix_all = df[numerical_cols].corr()
print(f"\nCorrelation Matrix Shape: {correlation_matrix_all.shape}")

# Find highly correlated feature pairs (> 0.7, excluding self-correlation)
high_corr_pairs = []
for i in range(len(correlation_matrix_all.columns)):
    for j in range(i + 1, len(correlation_matrix_all.columns)):
        if abs(correlation_matrix_all.iloc[i, j]) > 0.7:
            high_corr_pairs.append({
                'Feature 1': correlation_matrix_all.columns[i],
                'Feature 2': correlation_matrix_all.columns[j],
                'Correlation': correlation_matrix_all.iloc[i, j]
            })

if high_corr_pairs:
    print("\nHighly Correlated Feature Pairs (|correlation| > 0.7):")
    high_corr_df = pd.DataFrame(high_corr_pairs).sort_values('Correlation', key=abs, ascending=False)
    print(high_corr_df.to_string(index=False))
else:
    print("\nNo feature pairs with |correlation| > 0.7 found.")

# Visualize overall correlation matrix
fig, ax = plt.subplots(figsize=(16, 14))
mask = np.triu(np.ones_like(correlation_matrix_all, dtype=bool), k=1)
sns.heatmap(correlation_matrix_all, mask=mask, annot=False, cmap='coolwarm', 
            center=0, square=True, linewidths=0.3, cbar_kws={"shrink": 0.8}, ax=ax)
ax.set_title('Overall Feature Correlation Matrix (All Features)', fontsize=14, fontweight='bold', pad=20)
plt.xticks(rotation=45, ha='right', fontsize=9)
plt.yticks(rotation=0, fontsize=9)
plt.tight_layout()
plt.savefig('visualizations/correlation_matrix_all.png', dpi=300, bbox_inches='tight')
print("\n✓ Saved: visualizations/correlation_matrix_all.png")
plt.close()

# =====================================================================
# 8. Performance Metrics Summary
# =====================================================================
print("\n" + "=" * 80)
print("8. MODEL PERFORMANCE METRICS SUMMARY")
print("=" * 80)

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix, 
                            accuracy_score, precision_score, recall_score, 
                            f1_score, roc_auc_score, roc_curve)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"\nTrain set size: {X_train.shape[0]}")
print(f"Test set size: {X_test.shape[0]}")

# Make predictions
y_pred = rf_model.predict(X_test)
y_pred_proba = rf_model.predict_proba(X_test)[:, 1]

# Calculate metrics (with zero_division handling for string labels)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0, average='weighted')
recall = recall_score(y_test, y_pred, zero_division=0, average='weighted')
f1 = f1_score(y_test, y_pred, zero_division=0, average='weighted')
roc_auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', labels=rf_model.classes_)

print("\n" + "-" * 50)
print("PERFORMANCE METRICS")
print("-" * 50)
print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"F1-Score:  {f1:.4f}")
print(f"ROC-AUC:   {roc_auc:.4f}")

# Cross-validation scores
cv_scores = cross_val_score(rf_model, X, y, cv=5)
print(f"\nCross-Validation Scores (5-Fold):")
print(f"  Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
print(f"\nConfusion Matrix:")
print(cm)

# Classification report
print(f"\nDetailed Classification Report:")
print(classification_report(y_test, y_pred))

# Visualize performance metrics
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# 1. Confusion Matrix
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
            xticklabels=rf_model.classes_, yticklabels=rf_model.classes_)
axes[0, 0].set_title('Confusion Matrix', fontsize=12, fontweight='bold')
axes[0, 0].set_xlabel('Predicted')
axes[0, 0].set_ylabel('Actual')

# 2. ROC Curve - handle binary classification
if len(np.unique(y_test)) == 2:
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba, pos_label=y_test.unique()[1])
    axes[0, 1].plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.3f})', linewidth=2)
    axes[0, 1].plot([0, 1], [0, 1], 'k--', label='Random', linewidth=1)
    axes[0, 1].set_xlabel('False Positive Rate')
    axes[0, 1].set_ylabel('True Positive Rate')
    axes[0, 1].set_title('ROC Curve', fontsize=12, fontweight='bold')
    axes[0, 1].legend()
    axes[0, 1].grid(alpha=0.3)
else:
    axes[0, 1].text(0.5, 0.5, 'ROC Curve\n(Multi-class)', ha='center', va='center', fontsize=12)
    axes[0, 1].set_title('ROC Curve', fontsize=12, fontweight='bold')

# 3. Metrics Bar Chart
metrics_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']
metrics_values = [accuracy, precision, recall, f1, roc_auc]
colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
axes[1, 0].bar(metrics_names, metrics_values, color=colors, edgecolor='black', linewidth=1.5)
axes[1, 0].set_ylabel('Score')
axes[1, 0].set_title('Performance Metrics', fontsize=12, fontweight='bold')
axes[1, 0].set_ylim([0, 1])
axes[1, 0].tick_params(axis='x', rotation=45)
for i, v in enumerate(metrics_values):
    axes[1, 0].text(i, v + 0.02, f'{v:.3f}', ha='center', fontweight='bold')

# 4. Cross-validation scores
axes[1, 1].bar(range(1, len(cv_scores) + 1), cv_scores, color='#45B7D1', edgecolor='black', linewidth=1.5)
axes[1, 1].axhline(cv_scores.mean(), color='red', linestyle='--', linewidth=2, label=f'Mean: {cv_scores.mean():.3f}')
axes[1, 1].set_xlabel('Fold')
axes[1, 1].set_ylabel('Score')
axes[1, 1].set_title('Cross-Validation Scores (5-Fold)', fontsize=12, fontweight='bold')
axes[1, 1].legend()
axes[1, 1].set_ylim([0.9, 1.0])

plt.tight_layout()
plt.savefig('visualizations/performance_metrics.png', dpi=300, bbox_inches='tight')
print("\n✓ Saved: visualizations/performance_metrics.png")
plt.close()

# =====================================================================
# 9. Summary Report
# =====================================================================
print("\n" + "=" * 80)
print("ANALYSIS SUMMARY")
print("=" * 80)

summary_report = f"""
Dataset Overview:
  - Total Samples: {len(df)}
  - Numerical Features: {len(numerical_cols)}
  - Classes: {df[target_col].nunique()}
  - Class Imbalance: {(class_dist.max() / class_dist.min()):.2f}x

Feature Importance:
  - Top Feature: {feature_importance.iloc[0]['Feature']} ({feature_importance.iloc[0]['Importance']:.4f})
  - Top 3 Features: {', '.join(feature_importance.head(3)['Feature'].tolist())}

URL Analysis:
  - Average URL Length: {df['length_url'].mean():.2f}
  - URL Length Range: {df['length_url'].min():.0f} - {df['length_url'].max():.0f}

Correlation Insights:
  - Highly Correlated Pairs (>0.7): {len(high_corr_pairs)}
  
Model Performance:
  - Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)
  - Precision: {precision:.4f}
  - Recall: {recall:.4f}
  - F1-Score: {f1:.4f}
  - ROC-AUC: {roc_auc:.4f}
  - CV Mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}
"""

print(summary_report)

# Save summary report
with open('eda_summary_report.txt', 'w') as f:
    f.write("PHISHING WEBSITE DETECTION - EDA SUMMARY REPORT\n")
    f.write("=" * 80 + "\n")
    f.write(summary_report)
    f.write("\n\nTop 15 Features:\n")
    f.write(feature_importance.head(15).to_string())
    f.write("\n\n" + "=" * 80 + "\n")

print("\n✓ Saved: eda_summary_report.txt")
print("\n" + "=" * 80)
print("EDA ANALYSIS COMPLETE!")
print("=" * 80)
print("\nGenerated Visualizations:")
print("  1. visualizations/dataset_distribution.png")
print("  2. visualizations/url_length_distribution.png")
print("  3. visualizations/top_15_features.png")
print("  4. visualizations/correlation_matrix_top10.png")
print("  5. visualizations/correlation_matrix_all.png")
print("  6. visualizations/performance_metrics.png")
print("\nGenerated Reports:")
print("  1. eda_summary_report.txt")
print("=" * 80)
