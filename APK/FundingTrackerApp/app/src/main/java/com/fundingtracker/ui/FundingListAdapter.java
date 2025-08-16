package com.fundingtracker.ui;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.fundingtracker.model.FundingEntry;

import java.util.List;

public class FundingListAdapter extends ArrayAdapter<FundingEntry> {

    private final Context context;
    private final List<FundingEntry> fundingEntries;

    public FundingListAdapter(Context context, List<FundingEntry> fundingEntries) {
        super(context, 0, fundingEntries);
        this.context = context;
        this.fundingEntries = fundingEntries;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        FundingEntry fundingEntry = getItem(position);

        if (convertView == null) {
            convertView = LayoutInflater.from(context).inflate(com.fundingtracker.R.layout.item_funding, parent, false);
        }

        TextView amountTextView = convertView.findViewById(com.fundingtracker.R.id.amountTextView);
        TextView currencyTextView = convertView.findViewById(com.fundingtracker.R.id.currencyTextView);
        TextView dateTextView = convertView.findViewById(com.fundingtracker.R.id.dateTextView);

        amountTextView.setText(String.valueOf(fundingEntry.getAmount()));
        currencyTextView.setText(fundingEntry.getCurrency());
        dateTextView.setText(fundingEntry.getDate());

        return convertView;
    }
}