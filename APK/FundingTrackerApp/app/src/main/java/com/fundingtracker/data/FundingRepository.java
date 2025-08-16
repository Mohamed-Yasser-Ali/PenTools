package com.fundingtracker.data;

import com.fundingtracker.model.FundingEntry;
import java.util.ArrayList;
import java.util.List;

public class FundingRepository {
    private List<FundingEntry> fundingEntries;

    public FundingRepository() {
        fundingEntries = new ArrayList<>();
    }

    public void addFundingEntry(FundingEntry entry) {
        fundingEntries.add(entry);
    }

    public List<FundingEntry> getFundingEntries() {
        return fundingEntries;
    }

    public double calculateTotalFundingInUSD() {
        double total = 0;
        for (FundingEntry entry : fundingEntries) {
            if (entry.getCurrency().equals("USD")) {
                total += entry.getAmount();
            } else if (entry.getCurrency().equals("EGP")) {
                total += CurrencyConverter.convertToUSD(entry.getAmount());
            }
        }
        return total;
    }

    public double calculateTotalFundingInEGP() {
        double total = 0;
        for (FundingEntry entry : fundingEntries) {
            if (entry.getCurrency().equals("EGP")) {
                total += entry.getAmount();
            } else if (entry.getCurrency().equals("USD")) {
                total += CurrencyConverter.convertToEGP(entry.getAmount());
            }
        }
        return total;
    }
}