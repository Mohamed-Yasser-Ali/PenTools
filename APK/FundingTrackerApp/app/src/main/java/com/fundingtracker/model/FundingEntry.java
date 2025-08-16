public class FundingEntry {
    private double amount;
    private String currency;
    private String date;

    public FundingEntry(double amount, String currency, String date) {
        this.amount = amount;
        this.currency = currency;
        this.date = date;
    }

    public double getAmount() {
        return amount;
    }

    public void setAmount(double amount) {
        this.amount = amount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }
}