package com.fundingtracker;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.fundingtracker.data.FundingRepository;
import com.fundingtracker.model.FundingEntry;
import com.fundingtracker.ui.AddFundingActivity;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private FundingRepository fundingRepository;
    private TextView totalFundingTextView;
    private TextView totalEarningsTextView;
    private Button addFundingButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fundingRepository = new FundingRepository(this);
        totalFundingTextView = findViewById(R.id.totalFundingTextView);
        totalEarningsTextView = findViewById(R.id.totalEarningsTextView);
        addFundingButton = findViewById(R.id.addFundingButton);

        addFundingButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, AddFundingActivity.class);
                startActivity(intent);
            }
        });

        updateTotals();
    }

    private void updateTotals() {
        List<FundingEntry> fundingEntries = fundingRepository.getAllFundingEntries();
        double totalFunding = fundingRepository.calculateTotalFunding(fundingEntries);
        double totalEarnings = fundingRepository.calculateTotalEarnings(fundingEntries);

        totalFundingTextView.setText(String.format("Total Funding: $%.2f", totalFunding));
        totalEarningsTextView.setText(String.format("Total Earnings: EGP %.2f", totalEarnings));
    }
}