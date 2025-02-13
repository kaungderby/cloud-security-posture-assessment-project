import openai
import os
import time

# Load OpenAI API Key from environment variable
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def ask_user_for_genai():
    """Ask the user if they want to enable GenAI-powered recommendations."""
    response = input("Do you have an OpenAI API key and would you like to use GenAI-powered features? (yes/no): ").strip().lower()
    return response == "yes"

def get_openai_suggestion(finding):
    """Query OpenAI for remediation suggestions with rate-limit handling."""
    if not OPENAI_API_KEY:
        print("OpenAI API key not found. Skipping AI-generated recommendations.")
        return None
    
    prompt = f"Provide a best practice security recommendation for the following AWS security issue: {finding}"
    models = ["gpt-4o", "gpt-3.5-turbo"]
    retries = 3  # Max retries
    wait_time = 5  # Initial wait time in seconds
    
    for model in models:
        while retries > 0:
            try:
                client = openai.OpenAI(api_key=OPENAI_API_KEY)
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are an AWS security expert."},
                        {"role": "user", "content": prompt}
                    ]
                )
                return response.choices[0].message.content
            except openai.OpenAIError as e:
                if 'model_not_found' in str(e):
                    break
                elif 'insufficient_quota' in str(e) or 'rate limit' in str(e):
                    print(f"Rate limit exceeded. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    retries -= 1
                    wait_time = min(wait_time * 2, 60)
                else:
                    break
            except Exception:
                break
    print("No remediation suggestion available.")
    return None
