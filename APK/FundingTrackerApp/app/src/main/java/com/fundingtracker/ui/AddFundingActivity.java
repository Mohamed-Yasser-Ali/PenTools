package com.fundingtracker.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.fundingtracker.R;
import com.fundingtracker.data.FundingRepository;
import com.fundingtracker.model.FundingEntry;

import java.util.Date;

public class AddFundingActivity extends AppCompatActivity {

    private EditText amountEditText;
    private EditText currencyEditText;
    private Button saveButton;
    private FundingRepository fundingRepository;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_add_funding);

        amountEditText = findViewById(R.id.editTextAmount);
        currencyEditText = findViewById(R.id.editTextCurrency);
        saveButton = findViewById(R.id.buttonSave);
        fundingRepository = new FundingRepository(this);

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveFundingEntry();
            }
        });
    }

    private void saveFundingEntry() {
        String amountString = amountEditText.getText().toString();
        String currency = currencyEditText.getText().toString();

        if (amountString.isEmpty() || currency.isEmpty()) {
            Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show();
            return;
        }

        double amount = Double.parseDouble(amountString);
        FundingEntry entry = new FundingEntry(amount, currency, new Date());
        fundingRepository.addFundingEntry(entry);

        Toast.makeText(this, "Funding entry saved", Toast.LENGTH_SHORT).show();
        finish();
    }
}