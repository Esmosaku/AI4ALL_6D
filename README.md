# Phishing Detector for Emails and URLs 

Researched on the scale of phishing URLs and suspicious emails across the country, developing a phishing detector model based on over 800K rows of a URL dataset and a combination of 7 spam and non-spam email datasets with specifically chosen features, all within the AI4ALL Ignite accelerator.

## Problem Statement <!--- do not change this line -->

Based on our research, we discovered that there has been a steady and persistent growth rate of phishing URLs in emails and websites across the US and the world. With this, our goal was to build a solution that could help reduce this and allow users to detect these phishing URLs before clicking.

However, we discovered that there are products out there that can do this already. Therefore, to make our project unique, we deployed our model into a Chrome extension that users can use to scan emails regardless of whether the sender is an acquaintance. This eliminates the bias given to certain emails because they seem to be credible.

## Key Results <!--- do not change this line -->

1. Carried out feature engineering on the URL dataset with 48 self-made features based on behaviour patterns, not identity or language.
2. Combined 7 email datasets to make up the final email dataset with 21 self-made features and 768 features from Bert embeddings.
3. Due to imbalanced class distribution, to ensure fair training, we used 50% of each class to balance the dataset before training the models.
4. Able to successfully scan both phishing and safe emails and detect where and why they were either phishing or safe.

## Methodologies <!--- do not change this line -->

To accomplish this, we utilized pandas, numpy, and sklearn to clean the datasets, add features, and remove duplicates and outliers.
We used k-fold cross-validation to choose our initial model as well as hyperparameters for said model. From XGBoost, Random Forest, Logistic Regression, and Naive Bayes, we discovered that Logistic Regression had the best results.

## Data Sources <!--- do not change this line -->

Kaggle Datasets: [Link to Kaggle Dataset](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls) <br>
Email Datasets: [Link to Email Dataset](https://figshare.com/articles/dataset/Seven_Phishing_Email_Datasets/25432108)

## Technologies Used <!--- do not change this line -->

- Python
- pandas
- sklearn
- matplotlib
- numpy


## Authors <!--- do not change this line -->

This project was completed in collaboration with:
- Agamjot Singh ([john.doe@example.com](mailto:email.agamjotsingh@gmail.com))
- Esther Mosaku ([jane.smith@example.com](mailto:esmosaku@pugetsound.edu))
- Moo Muhammed ([jane.smith@example.com](mailto:mm5747@drexel.edu))
