
# Apache Superset Custom Authentication with JWT

This guide explains how to set up JWT (JSON Web Token) authentication in Apache Superset.

## Prerequisites

- Apache Superset installed and running
- Python 3.7+

## Installation

1. Install required packages:

pip install pyjwt
pip install python-dotenv


2. Create a `.env` file in your Superset root directory:

JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600


## Configuration

1. Update your Superset configuration to use the custom security manager:

Add the following to your `superset_config.py`:

`from custom_token_authentication import CustomSecurityManager`
`CUSTOM_SECURITY_MANAGER = CustomSecurityManager`

## Security Considerations

- Keep your JWT secret key secure and never commit it to version control
- Use strong secret keys
- Set appropriate token expiration times
- Use HTTPS in production
- Regularly rotate secret keys

## Troubleshooting

1. Ensure all environment variables are properly set
2. Check token expiration times
3. Verify the token format is correct
4. Confirm the security manager is properly configured

For more information, refer to:
- [Apache Superset Documentation](https://superset.apache.org/docs/security)
- [Flask-JWT Documentation](https://pythonhosted.org/Flask-JWT/)