package com.example.keystore

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import androidx.annotation.RequiresApi
import com.example.keystore.databinding.ActivityMainBinding
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {
    lateinit var binding: ActivityMainBinding

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val cryptoManager = CryptoManager()
        var message: String

        binding.btnEncrypt.setOnClickListener {
            val bytesToSave = binding.etText.text.toString().encodeToByteArray()
            val file = File(filesDir, "secret.txt")
            if (!file.exists()) {
                file.createNewFile()
            } else {
                val fos = FileOutputStream(file)
                message =
                    cryptoManager.encrypt(bytes = bytesToSave, outputStream = fos).decodeToString()
                binding.tvDecryptedText.text = "encrypted text: $message"
            }
        }

        binding.btnDecrypt.setOnClickListener {
            val file = File(filesDir, "secret.txt")
            message =
                cryptoManager.decrypt(inputStream = FileInputStream(file)).decodeToString()
            binding.tvDecryptedText.text = "decrypted text: $message"

        }
    }

}