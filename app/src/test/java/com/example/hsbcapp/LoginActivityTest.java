package com.example.hsbcapp;

import android.content.Intent;
import android.widget.Button;
import android.widget.EditText;

import androidx.biometric.BiometricPrompt;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.shadows.ShadowToast;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
public class LoginActivityTest {

    private LoginActivity activity;
    private EditText usernameField, passwordField;
    private Button submitButton, biometricLoginButton;

    @Mock
    private BiometricPrompt biometricPrompt;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        ActivityController<LoginActivity> controller = Robolectric.buildActivity(LoginActivity.class).create().start();
        activity = controller.get();

        usernameField = activity.findViewById(R.id.username);
        passwordField = activity.findViewById(R.id.password);
        submitButton = activity.findViewById(R.id.submit_button);
        biometricLoginButton = activity.findViewById(R.id.biometric_login);
    }

    @Test
    public void testAutofillCredentials() {
        assertEquals("admin", usernameField.getText().toString());
        assertEquals("1234", passwordField.getText().toString());
    }

    @Test
    public void testValidLogin() {
        usernameField.setText("admin");
        passwordField.setText("1234");

        submitButton.performClick();

        Intent expectedIntent = new Intent(activity, ImageUploadActivity.class);
        Intent actualIntent = shadowOf(activity).getNextStartedActivity();

        assertEquals(expectedIntent.getComponent(), actualIntent.getComponent());
    }

    @Test
    public void testInvalidLogin() {
        usernameField.setText("wrongUser");
        passwordField.setText("wrongPass");

        submitButton.performClick();

        // ✅ Fix: Using `getTextOfLatestToast()` instead of `getText()`
        String toastMessage = ShadowToast.getTextOfLatestToast();
        assertEquals("Invalid credentials", toastMessage);
    }

    @Test
    public void testBiometricLogin() {
        biometricLoginButton.performClick();

        // Simulate a successful biometric authentication
        BiometricPrompt.AuthenticationCallback callback = mock(BiometricPrompt.AuthenticationCallback.class);
        doAnswer(invocation -> {
            callback.onAuthenticationSucceeded(mock(BiometricPrompt.AuthenticationResult.class));
            return null;
        }).when(biometricPrompt).authenticate(any(BiometricPrompt.PromptInfo.class));

        verify(biometricPrompt).authenticate(any(BiometricPrompt.PromptInfo.class));
    }
}
