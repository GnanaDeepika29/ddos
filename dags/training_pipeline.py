"""Airflow DAG for model training pipeline.

This DAG orchestrates the offline training of machine learning models for
DDoS detection, including data preprocessing, feature engineering, model
training, and model deployment.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection.ml.trainer import ModelTrainer
from src.common.logging import get_logger

logger = get_logger(__name__)

default_args = {
    'owner': 'ddos-team',
    'depends_on_past': False,
    'start_date': days_ago(1),
    'email_on_failure': True,
    'email_on_retry': False,
    'email': ['alerts@ddos-defense.local'],
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}


def train_random_forest(**context):
    """Train Random Forest model."""
    data_path = context['params'].get('data_path', '/data/training/ddos_dataset.parquet')
    model_output_dir = context['params'].get('model_output_dir', '/opt/ddos-defense/models')
    trainer = ModelTrainer(
        data_path=data_path,
        model_output_dir=model_output_dir,
    )
    result = trainer.run_pipeline(model_type='rf', tune=False)
    logger.info(f"Random Forest training completed: {result['saved']}")
    # Push model path to XCom for downstream tasks
    context['task_instance'].xcom_push(key='rf_model_path', value=result['saved']['model_path'])
    return result['saved']


def train_xgboost(**context):
    """Train XGBoost model."""
    data_path = context['params'].get('data_path', '/data/training/ddos_dataset.parquet')
    model_output_dir = context['params'].get('model_output_dir', '/opt/ddos-defense/models')
    trainer = ModelTrainer(
        data_path=data_path,
        model_output_dir=model_output_dir,
    )
    result = trainer.run_pipeline(model_type='xgb', tune=False)
    logger.info(f"XGBoost training completed: {result['saved']}")
    context['task_instance'].xcom_push(key='xgb_model_path', value=result['saved']['model_path'])
    return result['saved']


def create_ensemble(**context):
    """Create ensemble model from individual models."""
    # This would combine the individual models into an ensemble
    # For now, we just log
    rf_path = context['task_instance'].xcom_pull(key='rf_model_path')
    xgb_path = context['task_instance'].xcom_pull(key='xgb_model_path')
    logger.info(f"Creating ensemble from {rf_path} and {xgb_path}")
    # In production, you would create an ensemble model (e.g., VotingClassifier)
    return {"ensemble_created": True}


def validate_model(**context):
    """Validate model performance on test set."""
    # Placeholder for model validation
    logger.info("Validating model")
    return {"validation_passed": True}


def deploy_model(**context):
    """Deploy model to production."""
    # Placeholder for model deployment (e.g., copy to production location)
    logger.info("Deploying model to production")
    return {"deployment_successful": True}


with DAG(
    'ddos_model_training',
    default_args=default_args,
    description='Train DDoS detection models',
    schedule_interval='0 0 * * 0',  # Weekly on Sunday at midnight
    catchup=False,
    tags=['ddos', 'ml', 'training'],
) as dag:

    # Task: Data validation
    validate_data = BashOperator(
        task_id='validate_data',
        bash_command='python /opt/ddos-defense/scripts/data_validation.py --data /data/training/ddos_dataset.parquet',
    )

    # Task: Train Random Forest
    train_rf = PythonOperator(
        task_id='train_random_forest',
        python_callable=train_random_forest,
        provide_context=True,
        params={
            'data_path': '/data/training/ddos_dataset.parquet',
            'model_output_dir': '/opt/ddos-defense/models',
        },
    )

    # Task: Train XGBoost
    train_xgb = PythonOperator(
        task_id='train_xgboost',
        python_callable=train_xgboost,
        provide_context=True,
        params={
            'data_path': '/data/training/ddos_dataset.parquet',
            'model_output_dir': '/opt/ddos-defense/models',
        },
    )

    # Task: Create ensemble
    create_ensemble_task = PythonOperator(
        task_id='create_ensemble',
        python_callable=create_ensemble,
        provide_context=True,
    )

    # Task: Validate model
    validate_model_task = PythonOperator(
        task_id='validate_model',
        python_callable=validate_model,
        provide_context=True,
    )

    # Task: Deploy model
    deploy_model_task = PythonOperator(
        task_id='deploy_model',
        python_callable=deploy_model,
        provide_context=True,
    )

    # Task: Send notification (optional)
    send_notification = BashOperator(
        task_id='send_notification',
        bash_command='echo "Model training completed" | mail -s "DDoS Model Training" alerts@ddos-defense.local',
    )

    # Define dependencies
    validate_data >> [train_rf, train_xgb]
    [train_rf, train_xgb] >> create_ensemble_task
    create_ensemble_task >> validate_model_task
    validate_model_task >> deploy_model_task
    deploy_model_task >> send_notification