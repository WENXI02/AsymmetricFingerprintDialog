package com.example.android.asymmetricfingerprintdialog;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

import javax.inject.Inject;

/**
 * Created by wenxi on 16/3/8.
 */
public abstract class BaseActivity extends Activity {


    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    /** Alias for our key in the Android Key Store */
    public static final String KEY_NAME = "my_key";

    @Inject
    KeyguardManager mKeyguardManager;
    @Inject
    FingerprintManager mFingerprintManager;
    @Inject FingerprintAuthenticationDialogFragment mFragment;
    @Inject
    KeyStore mKeyStore;
    @Inject
    KeyPairGenerator mKeyPairGenerator;
    @Inject
    Signature mSignature;
    @Inject
    SharedPreferences mSharedPreferences;

    @Inject SharedPreferences Fist_SharedPreferences;

    /**
     * 将结果返回
     * @param signature
     */
    public  abstract void  onPurchased(byte[] signature);

    /**
     * 识别失败
     */
    public  abstract void onPurchaseFailed();

//    /**
//     * 生成钥匙（包括公钥和私钥）
//     */
//    public abstract void createKeyPair();

    public void fingerprintLockStage(){
        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            //屏幕没有屏幕锁
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }
        //noinspection ResourceType
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            // This happens when no fingerprints are registered.
            //屏幕锁开启，没有指纹记录的时候出现
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }

    }
    /**
     * Generates an asymmetric key pair in the Android Keystore. Every use of the private key must
     * be authorized by the user authenticating with fingerprint. Public key use is unrestricted.
     */
    public void createKeyPair() {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            //初始化公钥和私钥的算法
            mKeyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            // Require the user to authenticate with a fingerprint to authorize
                            // every use of the private key
                            .setUserAuthenticationRequired(true)
                            .build());
            //计算并返回一个新的独特的安全KeyPair每次调用这个方法。KeyPair由公钥和私钥组成
            mKeyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Initialize the {@link Signature} instance with the created key in the
     * 生成私钥，初始化数字签名
     * {@link #createKeyPair()} method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    public boolean initSignature() {
        try {
            //keystore 为管理钥匙和用户的类
            mKeyStore.load(null);
            //获取私钥
            PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_NAME, null);
            //通过私钥初始化数字签名类
            mSignature.initSign(key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    /**
     * 弹出指纹识别对话框
     */
    public void  showFingerprintAuthenticationDialogFragment(){
        // Set up the crypto object for later. The object will be authenticated by use
        // of the fingerprint.
        if (initSignature()) {

            // Show the fingerprint dialog. The user has the option to use the fingerprint with
            // crypto, or you can fall back to using a server-side verified password.
            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mSignature));
            boolean isFist=Fist_SharedPreferences.getBoolean("Fist",true);
            if (isFist){
                mFragment.setStage(FingerprintAuthenticationDialogFragment.Stage.FISIST);
                mFragment.show(getFragmentManager(),DIALOG_FRAGMENT_TAG);
            }else{
                boolean useFingerprintPreference = mSharedPreferences
                        .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                                true);
                if (useFingerprintPreference) {
                    mFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
                } else {
                    mFragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                }
                mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
            }
        } else {
            // This happens if the lock screen has been disabled or or a fingerprint got
            // enrolled. Thus show the dialog to authenticate with their password first
            // and ask the user if they want to authenticate with fingerprints in the
            // future
            //当屏幕锁没有开启，或者是指纹传感器没有指纹时
            mFragment.setStage(
                    FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
            mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
        }

    }
}
