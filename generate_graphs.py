#!/usr/bin/env python3
"""
This script generates various graphs and visualizations for the research paper
based on the test results stored in the database.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import sqlite3
from database import DeObsDatabase
import argparse
import os
from pathlib import Path

# Set style for research paper quality
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class GraphGenerator:
    def __init__(self, db_path: str = "deobsbench.db", exclude_context_violations: bool = False):
        self.db = DeObsDatabase(db_path)
        self.output_dir = Path("graphs")
        self.output_dir.mkdir(exist_ok=True)
        self.exclude_context_violations = exclude_context_violations
        
    def get_model_data(self, run_id: str):
        """Get model performance data from database"""
        if self.exclude_context_violations:
            # Get filtered data excluding context violations
            return self._get_filtered_model_data(run_id)
        else:
            # Get all data
            accuracy = self.db.get_accuracy_summary(run_id)
            return accuracy['by_model']
    
    def _get_filtered_model_data(self, run_id: str):
        """Get model performance data excluding context violations"""
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Query for model data excluding context violations
        query = """
        SELECT 
            model_name,
            COUNT(*) as total_samples,
            COUNT(CASE WHEN success = 1 THEN 1 END) as successful_samples,
            AVG(processing_time) as avg_processing_time,
            AVG(f1_score) as avg_f1_score,
            AVG(precision) as avg_precision,
            AVG(recall) as avg_recall
        FROM sample_results 
        WHERE run_id = ? 
        AND sample_token_length IS NOT NULL 
        AND model_context_length IS NOT NULL
        AND sample_token_length <= model_context_length
        GROUP BY model_name
        ORDER BY avg_f1_score DESC
        """
        
        cursor.execute(query, (run_id,))
        results = cursor.fetchall()
        conn.close()
        
        # Convert to the same format as the original method
        model_data = []
        for row in results:
            model_name, total_samples, successful_samples, avg_processing_time, avg_f1_score, avg_precision, avg_recall = row
            model_data.append({
                'model_name': model_name,
                'total_samples': total_samples,
                'successful_samples': successful_samples,
                'avg_processing_time': avg_processing_time,
                'avg_f1_score': avg_f1_score,
                'avg_precision': avg_precision,
                'avg_recall': avg_recall
            })
        
        return model_data
    
    def clean_model_name(self, model_name: str) -> str:
        """Clean model name for display"""
        # Remove provider prefix and clean up names
        if '/' in model_name:
            model_name = model_name.split('/')[-1]
        
        # Replace underscores with spaces and title case
        model_name = model_name.replace('_', ' ').replace('-', ' ')
        return model_name.title()
    
    def create_accuracy_comparison(self, run_id: str, save_path: str = None):
        """Create accuracy comparison graph (F1 Score)"""
        data = self.get_model_data(run_id)
        
        # Prepare data
        models = []
        f1_scores = []
        precision_scores = []
        recall_scores = []
        
        for model in data:
            if model['avg_f1_score'] is not None:
                models.append(self.clean_model_name(model['model_name']))
                f1_scores.append(model['avg_f1_score'])
                precision_scores.append(model['avg_precision'] or 0)
                recall_scores.append(model['avg_recall'] or 0)
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create bar plot
        x = np.arange(len(models))
        width = 0.25
        
        bars1 = ax.bar(x - width, precision_scores, width, label='Precision', alpha=0.8)
        bars2 = ax.bar(x, recall_scores, width, label='Recall', alpha=0.8)
        bars3 = ax.bar(x + width, f1_scores, width, label='F1 Score', alpha=0.8)
        
        # Customize plot
        ax.set_xlabel('Models', fontsize=12, fontweight='bold')
        ax.set_ylabel('Score', fontsize=12, fontweight='bold')
        ax.set_title('Model Accuracy Comparison: Precision, Recall, and F1 Score', 
                    fontsize=14, fontweight='bold', pad=20)
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.legend(fontsize=11)
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 1.0)
        
        # Add value labels on bars
        def add_value_labels(bars):
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                       f'{height:.3f}', ha='center', va='bottom', fontsize=9)
        
        add_value_labels(bars1)
        add_value_labels(bars2)
        add_value_labels(bars3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Accuracy comparison graph saved to: {save_path}")
        
        return fig
    
    def create_success_rate_comparison(self, run_id: str, save_path: str = None):
        """Create success rate comparison graph"""
        data = self.get_model_data(run_id)
        
        # Prepare data
        models = []
        success_rates = []
        total_samples = []
        
        for model in data:
            models.append(self.clean_model_name(model['model_name']))
            success_rate = (model['successful_samples'] / model['total_samples']) * 100
            success_rates.append(success_rate)
            total_samples.append(model['total_samples'])
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create bar plot
        bars = ax.bar(models, success_rates, alpha=0.8, color='skyblue', edgecolor='navy', linewidth=1)
        
        # Customize plot
        ax.set_xlabel('Models', fontsize=12, fontweight='bold')
        ax.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
        ax.set_title('Model Success Rate Comparison', fontsize=14, fontweight='bold', pad=20)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.grid(True, alpha=0.3, axis='y')
        ax.set_ylim(0, 100)
        
        # Add value labels on bars
        for bar, rate in zip(bars, success_rates):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                   f'{rate:.1f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Success rate comparison graph saved to: {save_path}")
        
        return fig
    
    def create_processing_time_comparison(self, run_id: str, save_path: str = None):
        """Create processing time comparison graph"""
        data = self.get_model_data(run_id)
        
        # Prepare data
        models = []
        processing_times = []
        
        for model in data:
            if model['avg_processing_time'] is not None:
                models.append(self.clean_model_name(model['model_name']))
                processing_times.append(model['avg_processing_time'])
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create bar plot
        bars = ax.bar(models, processing_times, alpha=0.8, color='lightcoral', edgecolor='darkred', linewidth=1)
        
        # Customize plot
        ax.set_xlabel('Models', fontsize=12, fontweight='bold')
        ax.set_ylabel('Average Processing Time (seconds)', fontsize=12, fontweight='bold')
        ax.set_title('Model Processing Time Comparison', fontsize=14, fontweight='bold', pad=20)
        ax.set_xticklabels(models, rotation=45, ha='right')
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for bar, time in zip(bars, processing_times):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{time:.1f}s', ha='center', va='bottom', fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Processing time comparison graph saved to: {save_path}")
        
        return fig
    
    def create_performance_heatmap(self, run_id: str, save_path: str = None):
        """Create performance heatmap showing multiple metrics"""
        data = self.get_model_data(run_id)
        
        # Check if we have any data
        if not data:
            print("Warning: No model data available for heatmap. Skipping heatmap generation.")
            return None
        
        # Prepare data for heatmap
        models = [self.clean_model_name(model['model_name']) for model in data]
        metrics = ['Precision', 'Recall', 'F1 Score', 'Success Rate']
        
        # Create matrix
        matrix = []
        for model in data:
            row = []
            row.append(model['avg_precision'] or 0)
            row.append(model['avg_recall'] or 0)
            row.append(model['avg_f1_score'] or 0)
            success_rate = (model['successful_samples'] / model['total_samples']) * 100
            row.append(success_rate / 100)  # Normalize to 0-1
            matrix.append(row)
        
        matrix = np.array(matrix)
        
        # Check if matrix is empty
        if matrix.size == 0:
            print("Warning: Empty matrix for heatmap. Skipping heatmap generation.")
            return None
        
        # Create figure
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Create heatmap
        im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
        
        # Set ticks and labels
        ax.set_xticks(range(len(metrics)))
        ax.set_yticks(range(len(models)))
        ax.set_xticklabels(metrics)
        ax.set_yticklabels(models)
        
        # Add text annotations
        for i in range(len(models)):
            for j in range(len(metrics)):
                text = ax.text(j, i, f'{matrix[i, j]:.3f}',
                             ha="center", va="center", color="black", fontweight='bold')
        
        # Customize plot
        ax.set_title('Model Performance Heatmap', fontsize=14, fontweight='bold', pad=20)
        ax.set_xlabel('Metrics', fontsize=12, fontweight='bold')
        ax.set_ylabel('Models', fontsize=12, fontweight='bold')
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Score (0-1)', fontsize=11, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Performance heatmap saved to: {save_path}")
        
        return fig
    
    def create_context_length_analysis(self, run_id: str, save_path: str = None):
        """Create context length analysis graph showing accuracy vs context violations"""
        # Get detailed data from database
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        # Query for context length analysis
        if self.exclude_context_violations:
            # Exclude context violations
            query = """
            SELECT 
                model_name,
                COUNT(*) as total_samples,
                AVG(sample_token_length) as avg_token_length,
                MAX(sample_token_length) as max_token_length,
                model_context_length,
                0 as context_violations,
                COUNT(CASE WHEN success = 1 THEN 1 END) as successful_samples,
                AVG(CASE WHEN success = 1 THEN f1_score ELSE 0 END) as avg_f1_score,
                AVG(CASE WHEN success = 1 THEN precision ELSE 0 END) as avg_precision,
                AVG(CASE WHEN success = 1 THEN recall ELSE 0 END) as avg_recall
            FROM sample_results 
            WHERE sample_token_length IS NOT NULL 
            AND model_context_length IS NOT NULL
            AND sample_token_length <= model_context_length
            GROUP BY model_name
            ORDER BY avg_token_length DESC
            """
        else:
            # Include all data
            query = """
            SELECT 
                model_name,
                COUNT(*) as total_samples,
                AVG(sample_token_length) as avg_token_length,
                MAX(sample_token_length) as max_token_length,
                model_context_length,
                COUNT(CASE WHEN sample_token_length > model_context_length THEN 1 END) as context_violations,
                COUNT(CASE WHEN success = 1 THEN 1 END) as successful_samples,
                AVG(CASE WHEN success = 1 THEN f1_score ELSE 0 END) as avg_f1_score,
                AVG(CASE WHEN success = 1 THEN precision ELSE 0 END) as avg_precision,
                AVG(CASE WHEN success = 1 THEN recall ELSE 0 END) as avg_recall
            FROM sample_results 
            WHERE sample_token_length IS NOT NULL AND model_context_length IS NOT NULL
            GROUP BY model_name
            ORDER BY avg_token_length DESC
            """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        if not results:
            print("Warning: No context length data available. Skipping context length analysis.")
            conn.close()
            return None
        
        # Prepare data
        models = []
        violation_rates = []
        success_rates = []
        f1_scores = []
        context_lengths = []
        avg_token_lengths = []
        
        for row in results:
            model_name, total_samples, avg_tokens, max_tokens, context_length, violations, successful, f1, precision, recall = row
            
            # Clean model name
            clean_name = self.clean_model_name(model_name)
            models.append(clean_name)
            
            # Calculate rates
            violation_rate = (violations / total_samples) * 100
            success_rate = (successful / total_samples) * 100
            
            violation_rates.append(violation_rate)
            success_rates.append(success_rate)
            f1_scores.append(f1 or 0)
            context_lengths.append(context_length)
            avg_token_lengths.append(avg_tokens)
        
        # 2. F1 Score by Context Length Buckets
        # Get individual sample data for bucket analysis
        if self.exclude_context_violations:
            sample_query = """
            SELECT 
                sample_token_length,
                f1_score,
                success,
                model_name
            FROM sample_results 
            WHERE sample_token_length IS NOT NULL 
            AND f1_score IS NOT NULL
            AND sample_token_length <= model_context_length
            ORDER BY sample_token_length
            """
        else:
            sample_query = """
            SELECT 
                sample_token_length,
                f1_score,
                success,
                model_name
            FROM sample_results 
            WHERE sample_token_length IS NOT NULL AND f1_score IS NOT NULL
            ORDER BY sample_token_length
            """
        
        cursor.execute(sample_query)
        sample_results = cursor.fetchall()
        conn.close()
        
        # Create figure with 2 subplots side by side
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # 1. Context Violations vs Success Rate
        colors = ['red' if v > 0 else 'green' for v in violation_rates]
        bars1 = ax1.bar(models, violation_rates, alpha=0.7, color=colors, edgecolor='black', linewidth=1)
        ax1.set_xlabel('Models', fontsize=11, fontweight='bold')
        ax1.set_ylabel('Context Violation Rate (%)', fontsize=11, fontweight='bold')
        ax1.set_title('Context Length Violations by Model', fontsize=12, fontweight='bold')
        ax1.set_xticklabels(models, rotation=45, ha='right')
        ax1.grid(True, alpha=0.3, axis='y')
        
        # Add value labels
        for bar, rate in zip(bars1, violation_rates):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{rate:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        if sample_results:
            # Create context length buckets
            token_lengths = [row[0] for row in sample_results]
            f1_scores = [row[1] for row in sample_results]
            success_flags = [row[2] for row in sample_results]
            
            # Define 10 granular bucket ranges based on common context lengths
            bucket_ranges = [
                (0, 5000, "0-5K"),
                (5000, 15000, "5K-15K"),
                (15000, 30000, "15K-30K"),
                (30000, 50000, "30K-50K"),
                (50000, 100000, "50K-100K"),
                (100000, 150000, "100K-150K"),
                (150000, 200000, "150K-200K"),
                (200000, 300000, "200K-300K"),
                (300000, 500000, "300K-500K"),
                (500000, float('inf'), "500K+")
            ]
            
            bucket_data = []
            bucket_labels = []
            bucket_colors = []
            
            for min_tokens, max_tokens, label in bucket_ranges:
                # Filter samples in this bucket
                bucket_f1s = []
                bucket_successes = []
                
                for i, (tokens, f1, success) in enumerate(zip(token_lengths, f1_scores, success_flags)):
                    if min_tokens <= tokens < max_tokens:
                        bucket_f1s.append(f1)
                        bucket_successes.append(success)
                
                
                if bucket_f1s:  # Buckets with data
                    avg_f1 = np.mean(bucket_f1s)
                    success_rate = np.mean(bucket_successes) * 100
                    sample_count = len(bucket_f1s)
                else:  # Empty buckets
                    avg_f1 = 0.0
                    success_rate = 0.0
                    sample_count = 0
                
                bucket_data.append(avg_f1)
                bucket_labels.append(f"{label}\n(n={sample_count})")
                
                # Color based on success rate
                if success_rate >= 80:
                    bucket_colors.append('green')
                elif success_rate >= 50:
                    bucket_colors.append('orange')
                else:
                    bucket_colors.append('red')
            
            # Create bar chart
            bars2 = ax2.bar(bucket_labels, bucket_data, alpha=0.7, color=bucket_colors, 
                           edgecolor='black', linewidth=1)
            ax2.set_xlabel('Context Length Buckets (Tokens)', fontsize=11, fontweight='bold')
            ax2.set_ylabel('Average F1 Score', fontsize=11, fontweight='bold')
            ax2.set_title('F1 Score by Context Length Buckets', fontsize=12, fontweight='bold')
            ax2.grid(True, alpha=0.3, axis='y')
            ax2.set_ylim(0, 1.0)
            
            # Add value labels on bars
            for bar, f1_score in zip(bars2, bucket_data):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                       f'{f1_score:.3f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
            
            # Add legend for color coding
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='green', alpha=0.7, label='High Success (≥80%)'),
                Patch(facecolor='orange', alpha=0.7, label='Medium Success (50-79%)'),
                Patch(facecolor='red', alpha=0.7, label='Low Success (<50%)')
            ]
            ax2.legend(handles=legend_elements, loc='upper right', fontsize=9)
        else:
            ax2.text(0.5, 0.5, 'No sample data available', ha='center', va='center', 
                    transform=ax2.transAxes, fontsize=12)
            ax2.set_title('F1 Score by Context Length Buckets', fontsize=12, fontweight='bold')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Context length analysis saved to: {save_path}")
        
        return fig
    
    def create_all_graphs(self, run_id: str):
        """Create all graphs for the research paper"""
        exclusion_note = " (excluding context violations)" if self.exclude_context_violations else ""
        print(f"Generating graphs for test run: {run_id}{exclusion_note}")
        print("=" * 50)
        
        # Create all graphs
        self.create_accuracy_comparison(run_id, self.output_dir / "accuracy_comparison.png")
        self.create_success_rate_comparison(run_id, self.output_dir / "success_rate_comparison.png")
        self.create_processing_time_comparison(run_id, self.output_dir / "processing_time_comparison.png")
        self.create_performance_heatmap(run_id, self.output_dir / "performance_heatmap.png")
        self.create_context_length_analysis(run_id, self.output_dir / "context_length_analysis.png")
        
        print(f"\nAll graphs saved to: {self.output_dir}")
        print("Graphs generated:")
        print("- accuracy_comparison.png: Precision, Recall, and F1 Score comparison")
        print("- success_rate_comparison.png: Success rate by model")
        print("- processing_time_comparison.png: Processing time by model")
        print("- performance_heatmap.png: Multi-metric performance heatmap")
        print("- context_length_analysis.png: Context length violations and accuracy analysis")
        if self.exclude_context_violations:
            print("\nNote: All graphs exclude samples where token length > model context length")

def main():
    parser = argparse.ArgumentParser(description='Generate graphs for DeObsBench research paper')
    parser.add_argument('--run-id', required=True, help='Test run ID to generate graphs for')
    parser.add_argument('--db-path', default='deobsbench.db', help='Path to database file')
    parser.add_argument('--output-dir', default='graphs', help='Output directory for graphs')
    parser.add_argument('--exclude-context-violations', action='store_true', 
                       help='Exclude samples where token length > model context length')
    
    args = parser.parse_args()
    
    # Create graph generator
    generator = GraphGenerator(args.db_path, args.exclude_context_violations)
    generator.output_dir = Path(args.output_dir)
    generator.output_dir.mkdir(exist_ok=True)
    
    # Generate all graphs
    generator.create_all_graphs(args.run_id)

if __name__ == "__main__":
    main()
