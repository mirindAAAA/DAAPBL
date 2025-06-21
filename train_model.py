# train_model.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import joblib
import os

def train_model(dataset_path: str = 'emails.csv', model_output_path: str = 'phishing_model.pkl'):
    """
    Train a phishing detection model and save it to disk
    
    Args:
        dataset_path: Path to CSV file (default: emails.csv in same directory)
        model_output_path: Where to save the trained model (default: phishing_model.pkl)
    """
    # Verify dataset exists
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at {os.path.abspath(dataset_path)}")
    
    print(f"Loading dataset from {os.path.abspath(dataset_path)}")
    try:
        data = pd.read_csv(dataset_path)
        
        # Verify required columns exist
        required_columns = {'subject', 'text', 'label'}
        if not required_columns.issubset(data.columns):
            missing = required_columns - set(data.columns)
            raise ValueError(f"Dataset missing required columns: {missing}")
            
    except Exception as e:
        print(f"Error loading dataset: {str(e)}")
        return

    # Combine subject and text for better features
    data['combined_text'] = data['subject'].fillna('') + ' ' + data['text'].fillna('')
    
    # Split into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        data['combined_text'], 
        data['label'], 
        test_size=0.2, 
        random_state=42,
        stratify=data['label']  # Maintain class distribution
    )
    
    print("\nDataset Statistics:")
    print(f"- Total samples: {len(data)}")
    print(f"- Training samples: {len(X_train)}")
    print(f"- Test samples: {len(X_test)}")
    print(f"- Phishing ratio: {data['label'].mean():.2%}\n")
    
    # Create pipeline with TF-IDF and Naive Bayes
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=10000,
            stop_words='english',
            ngram_range=(1, 2),  # Include bigrams
            sublinear_tf=True     # Use log scaling
        )),
        ('classifier', MultinomialNB(
            alpha=0.1,           # Smoothing parameter
            fit_prior=True        # Learn class prior probabilities
        ))
    ])
    
    # Train model
    print("Training model...")
    pipeline.fit(X_train, y_train)
    
    # Evaluate
    train_score = pipeline.score(X_train, y_train)
    test_score = pipeline.score(X_test, y_test)
    print(f"\nModel Performance:")
    print(f"- Training accuracy: {train_score:.4f}")
    print(f"- Test accuracy: {test_score:.4f}")
    
    # Additional metrics
    from sklearn.metrics import classification_report
    y_pred = pipeline.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save model
    try:
        joblib.dump(pipeline, model_output_path)
        print(f"\nModel successfully saved to {os.path.abspath(model_output_path)}")
    except Exception as e:
        print(f"\nError saving model: {str(e)}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Train phishing email detection model',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--dataset', 
        help='Path to CSV dataset (subject,text,label)',
        default='emails.csv'
    )
    parser.add_argument(
        '--output', 
        help='Output path for trained model',
        default='phishing_model.pkl'
    )
    args = parser.parse_args()
    
    train_model(args.dataset, args.output)