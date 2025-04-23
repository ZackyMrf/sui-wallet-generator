# SUI Wallet Generator

A comprehensive toolkit for generating SUI blockchain wallets and automating test token requests from the SUI testnet faucet.

---

## 📋 Overview

This project provides tools to:
1. Generate secure SUI blockchain wallets (with addresses, private keys, and mnemonics).
2. Batch create multiple wallets.
3. Request test tokens from the SUI testnet faucet.
4. Manage wallet information securely.

---

## ✨ Features

### 🚀 Wallet Generator
- **Multiple Seed Generation Methods**: Generate wallets using random seeds or passphrase-based seeds.
- **BIP-39 Mnemonic Support**: Recover wallets using mnemonic phrases.
- **Batch Wallet Creation**: Create multiple wallets at once.
- **Secure Cryptographic Implementations**: Ensure wallet security with industry-standard cryptographic practices.
- **Organized Wallet Information Storage**: Store wallet addresses, private keys, and mnemonics in structured files.

---

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/zackymrf/sui-wallet-generator.git
   cd sui-wallet-generator
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

### 🔑 Generating Wallets

#### Single Wallet
Run the following command and follow the interactive prompts to create a single wallet:
```bash
python wallet.py
```
linux
```bash
python3 wallet.py
```
#### Multiple Wallets
Create multiple wallets at once:
- Using random seed generation:
  ```bash
  python wallet.py --count 10 --random
  ```
- Using a secure passphrase:
  ```bash
  python wallet.py --count 10 --passphrase "your-secure-passphrase"
  ```

---

### 💰 Using the Faucet Bot

1. Ensure your wallet addresses are listed in `wallet.txt`.
2. (Optional) Add proxy configurations to `proxies.txt` (each proxy on a single line in one of the following formats):
   - `http://username:password@ip:port`
   - `ip:port`
3. Run the faucet bot:
   ```bash
   python faucet.py
   ```
4. When prompted, complete the Cloudflare Turnstile challenge in your browser and provide the token.

---


---

## 🔒 Security Notes

- **NEVER** share your private keys or mnemonic phrases.
- Keep your wallet files secure, as they contain sensitive information.
- Consider encrypting wallet files when not in use.
- Use a secure, unique passphrase for passphrase-based wallet generation.
- This tool is for **educational and development purposes only**.

---

## ⚠️ Important Considerations

- The **SUI faucet** is rate-limited and requires a valid Cloudflare Turnstile token.
- Excessive requests may result in blocks by the faucet service.
- Test tokens from the SUI testnet have **no real monetary value**.
- Only request tokens for legitimate development or testing purposes.

---

## 🔍 Troubleshooting

### Common Issues

1. **"MissingTurnstileTokenHeader" Error**:
   - The faucet now requires a valid Cloudflare Turnstile token.
   - Follow the browser instructions to obtain a token manually.

2. **Connection Errors with Proxies**:
   - Verify the format of proxies in `proxies.txt`.
   - Ensure proxies are operational and not blocked.

3. **Wallet Generation Errors**:
   - Ensure you have the latest cryptography packages installed.
   - Check if your system has enough entropy for secure random generation.

---

## 📜 License

This project is licensed for **educational purposes only**. Please use it responsibly.

---

## 🙏 Acknowledgements

- **SUI Blockchain Documentation**: For insights into wallet generation and faucet handling.
- **BIP-39 Mnemonic Standard**: For wallet recovery implementation.
- **Python Cryptography Libraries**: For secure cryptographic operations.

---

**Note**: This tool is not affiliated with or endorsed by SUI or Mysten Labs.