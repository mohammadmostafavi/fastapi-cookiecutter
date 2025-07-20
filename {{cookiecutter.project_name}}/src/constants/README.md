# Constants

This directory contains constant values used throughout the application. Centralizing constants in this directory makes it easier to maintain and update them.

## Contents

- `__init__.py`: Package initialization file
- `app.py`: Application-wide constants
- `auth.py`: Authentication and authorization constants
- `database.py`: Database-related constants

## Usage

Constants can be imported and used in other modules. For example:

```python
from src.constants.app import APP_NAME
from src.constants.database import DEFAULT_POSTGRESQL_URL
from src.constants.auth import JWT_ALGORITHM

# Use the constants
print(f"Application name: {APP_NAME}")
db_url = os.getenv("DB_URL", DEFAULT_POSTGRESQL_URL)
```

## Adding New Constants

When adding new constants, follow these guidelines:

1. Group related constants in the appropriate file
2. Create a new file if the constants don't fit into existing categories
3. Use UPPER_CASE for constant names
4. Add comments to explain the purpose and usage of constants
5. Use descriptive names for constants

## Types of Constants

- **Configuration Constants**: Default values for configuration settings
- **Business Logic Constants**: Values used in business logic
- **UI Constants**: Values used in the user interface
- **Error Constants**: Error codes and messages