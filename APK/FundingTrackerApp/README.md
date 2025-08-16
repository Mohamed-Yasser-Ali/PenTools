# Funding Tracker App

## Overview
The Funding Tracker App is designed to help users track their monthly funding and earnings. It allows users to input funding entries, view totals in both US dollars and Egyptian pounds, and manage their financial data efficiently.

## Features
- Add new funding entries with details such as amount, currency, and date.
- View a list of all funding entries.
- Calculate and display total funding and earnings in both US dollars and Egyptian pounds.
- User-friendly interface for easy navigation and data entry.

## Project Structure
```
FundingTrackerApp
├── app
│   ├── src
│   │   ├── main
│   │   │   ├── java
│   │   │   │   └── com
│   │   │   │       └── fundingtracker
│   │   │   │           ├── MainActivity.java
│   │   │   │           ├── data
│   │   │   │           │   └── FundingRepository.java
│   │   │   │           ├── model
│   │   │   │           │   └── FundingEntry.java
│   │   │   │           ├── ui
│   │   │   │           │   ├── FundingListAdapter.java
│   │   │   │           │   └── AddFundingActivity.java
│   │   │   │           └── utils
│   │   │   │               └── CurrencyConverter.java
│   │   │   ├── res
│   │   │   │   ├── layout
│   │   │   │   │   ├── activity_main.xml
│   │   │   │   │   └── item_funding.xml
│   │   │   │   ├── values
│   │   │   │   │   ├── strings.xml
│   │   │   │   │   └── colors.xml
│   │   │   │   └── AndroidManifest.xml
│   └── build.gradle
├── build.gradle
└── README.md
```

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/FundingTrackerApp.git
   ```
2. Open the project in Android Studio.
3. Build the project to download dependencies.

## Usage
- Launch the app and navigate to the main screen.
- Use the "Add Funding" button to input new funding entries.
- View the list of entries and the calculated totals on the main screen.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.