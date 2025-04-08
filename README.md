# QuantumPass - Quantum-Enhanced Password Manager

![QuantumPass Poster](a3%20poster.jpg)

## Overview

QuantumPass is a cutting-edge password manager that combines classical encryption with quantum computing verification. It leverages Amazon's SV1 quantum simulator to provide an additional layer of security through quantum verification of stored passwords.

## Features

- 🔐 **Classical Encryption**: Secure password storage using Fernet encryption
- 🌌 **Quantum Verification**: Password verification using Amazon's SV1 quantum simulator
- ☁️ **Cloud Storage**: Secure storage in AWS S3
- 🔑 **Vault Management**: Create and manage multiple password vaults
- 🔒 **Session Management**: Secure user authentication and session handling
- 🎨 **Modern UI**: Clean and intuitive user interface

## Technology Stack

- **Backend**: Python, Flask
- **Database**: SQLite
- **Cloud**: AWS S3, Amazon Braket
- **Quantum**: Amazon SV1 Simulator
- **Frontend**: HTML, CSS, JavaScript

## Prerequisites

- Python 3.8+
- AWS Account with:
  - S3 Bucket
  - Amazon Braket access
  - IAM credentials

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/quantum-pass.git
cd quantum-pass
```

2. Create and activate virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure environment variables:

Create a `.env` file with:

```
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_BUCKET_NAME=your_bucket_name
AWS_REGION=us-east-1
BRAKET_BUCKET_NAME=your_braket_bucket
BRAKET_REGION=us-east-1
```

## Running the Application

1. Start the Flask server:

```bash
python app.py
```

2. Open your browser and navigate to:

```
http://127.0.0.1:5000
```

## Security Features

- **Classical Encryption**: Passwords are encrypted using Fernet (symmetric encryption)
- **Quantum Verification**: Each password is verified using quantum circuits
- **Secure Storage**: Encrypted passwords are stored in AWS S3
- **Session Management**: Secure user sessions with proper authentication

## Project Structure

```
quantum-pass/
├── app.py                 # Main Flask application
├── quantum_encryption.py  # Quantum verification logic
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
├── static/              # Static assets
└── .env                 # Environment variables
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Amazon Web Services for S3 and Braket services
- Flask framework
- Quantum computing community

## Contact

Your Name - [@yourtwitter](https://twitter.com/yourtwitter)

Project Link: [https://github.com/yourusername/quantum-pass](https://github.com/yourusername/quantum-pass)
