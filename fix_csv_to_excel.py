import pandas as pd

df = pd.read_csv("cicids2017_cleaned.csv")

# Shuffle the full dataset
df_shuffled = df.sample(frac=1, random_state=42)

# Take only top 500 rows
top_500 = df_shuffled.head(500)

# Save to Excel
top_500.to_excel("cicids2017_top_500.xlsx", index=False)

print("Top 500 rows (mixed Normal + Attack) created")
  