package com.example.paytmimpl

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.example.paytmimpl.checksum.CheckSumServiceHelper
import com.paytm.pgsdk.PaytmOrder
import com.paytm.pgsdk.PaytmPGService
import com.paytm.pgsdk.PaytmPaymentTransactionCallback
import kotlinx.android.synthetic.main.activity_main.*
import java.util.*
import kotlin.collections.HashMap


class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        if (ContextCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.READ_SMS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this@MainActivity,
                arrayOf(
                    Manifest.permission.READ_SMS,
                    Manifest.permission.RECEIVE_SMS
                ), 101
            )
        }
        start.setOnClickListener {
            useinapp()
        }
    }

    private fun useinapp() {
        val instance = this
        val mContext = applicationContext
        val Service = PaytmPGService.getStagingService("")
        val orderid = "order" + (0..99999).random()
        val custid = "cust" + (0..99999).random()
        val amount = "100.20"
        val paramMap = HashMap<String, String>()
        Log.d("orderid", orderid)
        Log.d("custid", custid)
        paramMap.put("MID", Keys.MID)
        paramMap.put("ORDER_ID", orderid)
        paramMap.put("WEBSITE", "WEBSTAGING")
        paramMap.put("INDUSTRY_TYPE_ID", "Retail");
        paramMap.put("CHANNEL_ID", "WAP");
        paramMap.put("CUST_ID", custid);
        paramMap.put("TXN_AMOUNT", amount);
        paramMap.put(
            "CALLBACK_URL",
            "https://securegw-stage.paytm.in/theia/paytmCallback?ORDER_ID=${orderid}"
        );

        val paramMap2 = TreeMap<String, String>()
        paramMap2.putAll(paramMap)
//        paramMap.putAll(paramMap2)
        var CHECKSUMHASH =
            CheckSumServiceHelper().genrateCheckSum(
                Keys.MID_KEY,
                paramMap2
            )

        paramMap.put("CHECKSUMHASH", CHECKSUMHASH)
        val Order = PaytmOrder(paramMap)
        Service.initialize(Order, null);
        Service.startPaymentTransaction(
            instance,
            true,
            true,
            object : PaytmPaymentTransactionCallback {
                /*Call Backs*/
                override fun someUIErrorOccurred(inErrorMessage: String) {
                    Toast.makeText(
                        mContext,
                        "UI Error $inErrorMessage",
                        Toast.LENGTH_LONG
                    ).show();
                    Log.d("messsage", inErrorMessage)

                }

                override fun onTransactionResponse(inResponse: Bundle) {
                    Toast.makeText(
                        mContext,
                        "Payment Transaction response $inResponse",
                        Toast.LENGTH_LONG
                    ).show();
                    Log.d("messsage", inResponse.toString())

                }

                override fun networkNotAvailable() {
                    Toast.makeText(mContext, "Net prob", Toast.LENGTH_SHORT)
                        .show()
                }

                override fun clientAuthenticationFailed(inErrorMessage: String) {
                    Toast.makeText(
                        mContext,
                        "Authentication failed: Server error" + inErrorMessage.toString(),
                        Toast.LENGTH_LONG
                    ).show();
                    Log.d("messsage", inErrorMessage)
                }

                override fun onErrorLoadingWebPage(
                    iniErrorCode: Int,
                    inErrorMessage: String,
                    inFailingUrl: String
                ) {
                    Toast.makeText(
                        mContext,
                        "Unable to load webpage $inErrorMessage", Toast.LENGTH_LONG
                    ).show();
                    Log.d("messsage", inErrorMessage)
                }

                override fun onBackPressedCancelTransaction() {

                }

                override fun onTransactionCancel(
                    inErrorMessage: String,
                    inResponse: Bundle
                ) {
                    Toast.makeText(
                        mContext,
                        "Transaction cancelled",
                        Toast.LENGTH_LONG
                    ).show();
                    Log.d("messsage", inErrorMessage)
                }
            })

    }
}

