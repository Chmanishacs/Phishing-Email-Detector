Cloud-Assisted Phishing Email Detector and Incident Response Dashboard
A Python/Flask lab project that analyzes saved .eml files, explains why a message looks suspicious, and tracks a simulated incident response. It includes optional AWS S3 code that has not yet been tested on a real AWS account.
Detection screen
Features
Explainable 0-100 risk score (a level of concern, not a probability)
Sender, Reply-To, URL, language, attachment-name and reported SPF/DKIM/DMARC checks
Quarantine, release, eradicate (adds sender domain to a blocklist), close, analyst notes
Sanitized JSON report with no body, addresses, URLs or notes
Optional AWS S3 upload and S3-triggered Lambda (not yet tested on real AWS)
Architecture
.eml file -> parser -> rules -> SQLite -> Flask dashboard (127.0.0.1)
                                              |
                                     sanitized report -> private S3 bucket
Optional: S3 input bucket -> Lambda (same parser and rules) -> S3 output bucket
Run it (macOS)
Needs Python 3.10 or newer (python3 --version).
bash
cd phishing-email-detector
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
python app.py
Open http://127.0.0.1:5001 and upload a file from samples/. Press Ctrl+C to stop.
Evaluation
bash
python evaluate.py data/dev
python evaluate.py data/test
Set	Emails	Precision	Recall	False positives	False negatives
Development	6	1.00	1.00	0	0
Test	10	0.75	0.60	1	2
Test confusion matrix: TP 3, FN 2, FP 1, TN 4. "Positive" means score 30 or higher. Misses: a payment-change request with no link, and a shortened "shared file" link. False alarm: a gift card giveaway.
AWS setup (optional)
In AWS Budgets, create a small budget alert. Alerts can be delayed and are not a spending cap.
Create an S3 bucket and keep Block all public access on.
Create an IAM identity limited to cloud/iam-policy.json (replace the bucket name). Prefer temporary credentials; never put keys in the code or in GitHub.
Configure credentials with the AWS CLI, then:
bash
pip install -r requirements-cloud.txt
REPORT_BUCKET=your-bucket-name python app.py
Click Upload report to S3 and confirm the object under reports/.
Delete the objects, bucket and credentials when finished.
Optional Lambda
Use two different buckets (input and output).
Zip the code: zip -r lambda.zip detector cloud -x '*__pycache__*'
Create a Python Lambda, upload the zip, set handler cloud.lambda_function.lambda_handler and environment variable OUTPUT_BUCKET.
Role: basic Lambda logging, s3:GetObject on the input bucket, s3:PutObject on output-bucket/reports/*.
Add an S3 "object created" trigger on the input bucket with suffix .eml.
Upload synthetic emails only. Check logs in CloudWatch.
The Lambda does not use the dashboard's local blocklist.
Limitations
Small, synthetic, English-only data written by the same source as the rules. Results do not show real-world accuracy.
SPF/DKIM/DMARC values are read from the file and are not verified; headers can be forged.
Attachments are checked by file name only.
Quarantine changes a status in this app. It does not touch any real mailbox.
Single-user local lab with no login. Do not host it on the internet.
S3 and Lambda code is tested with a stand-in client; verify it in your own AWS account.
Safety
Use synthetic or sanitized emails. Never commit real mail, credentials or the instance/ folder.
Possible next step
Compare the rules with a scikit-learn text classifier on a larger, properly licensed dataset, keeping test data separate from training data.
Acknowledgment
Initial code and documentation were drafted with AI assistance.
