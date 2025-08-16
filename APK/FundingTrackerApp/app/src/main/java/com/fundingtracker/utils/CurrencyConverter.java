package com.fundingtracker.utils;

public class CurrencyConverter {
    private static final double USD_TO_EGP_RATE = 30.9; // Example conversion rate

    public static double convertUSDtoEGP(double amountInUSD) {
        return amountInUSD * USD_TO_EGP_RATE;
    }

    public static double convertEGPtoUSD(double amountInEGP) {
        return amountInEGP / USD_TO_EGP_RATE;
    }
}