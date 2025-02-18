package com.example.hsbcapp;

import androidx.test.core.app.ActivityScenario;
import androidx.test.espresso.intent.Intents;
import androidx.test.ext.junit.rules.ActivityScenarioRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.closeSoftKeyboard;
import static androidx.test.espresso.action.ViewActions.replaceText;
import static androidx.test.espresso.action.ViewActions.typeText;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.intent.Intents.intended;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.matcher.RootMatchers.withDecorView;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

@RunWith(AndroidJUnit4.class)
@LargeTest
public class LoginActivityTest {

    @Rule
    public ActivityScenarioRule<LoginActivity> activityRule =
            new ActivityScenarioRule<>(LoginActivity.class);

    private android.view.View decorView;

    @Before
    public void setUp() {
        Intents.init();
        activityRule.getScenario().onActivity(activity -> {
            decorView = activity.getWindow().getDecorView();
        });
    }

    @After
    public void tearDown() {
        Intents.release();
    }

    @Test
    public void testInitialViewsDisplayed() {
        // Verify all views are displayed
        onView(withId(R.id.logo)).check(matches(isDisplayed()));
        onView(withId(R.id.username)).check(matches(isDisplayed()));
        onView(withId(R.id.password)).check(matches(isDisplayed()));
        onView(withId(R.id.submit_button)).check(matches(isDisplayed()));
        onView(withId(R.id.biometric_login)).check(matches(isDisplayed()));
    }

    @Test
    public void testPrefilledCredentials() {
        // Verify username and password are pre-filled
        onView(withId(R.id.username)).check(matches(withText("admin")));
        onView(withId(R.id.password)).check(matches(withText("1234")));
    }

    @Test
    public void testSuccessfulLogin() {
        // Clear and type correct credentials
        onView(withId(R.id.username))
                .perform(replaceText("admin"), closeSoftKeyboard());
        onView(withId(R.id.password))
                .perform(replaceText("1234"), closeSoftKeyboard());

        // Click submit
        onView(withId(R.id.submit_button)).perform(click());

        // Verify navigation to ImageUploadActivity
        intended(hasComponent(ImageUploadActivity.class.getName()));
    }

    @Test
    public void testFailedLogin() {
        // Type incorrect credentials
        onView(withId(R.id.username))
                .perform(replaceText("wrong"), closeSoftKeyboard());
        onView(withId(R.id.password))
                .perform(replaceText("wrong"), closeSoftKeyboard());

        // Click submit
        onView(withId(R.id.submit_button)).perform(click());

        // Verify error toast is shown
        onView(withText("Invalid credentials"))
                .inRoot(withDecorView(not(is(decorView))))
                .check(matches(isDisplayed()));
    }

    @Test
    public void testEmptyCredentials() {
        // Clear credentials
        onView(withId(R.id.username)).perform(replaceText(""));
        onView(withId(R.id.password)).perform(replaceText(""));

        // Click submit
        onView(withId(R.id.submit_button)).perform(click());

        // Verify error toast
        onView(withText("Invalid credentials"))
                .inRoot(withDecorView(not(is(decorView))))
                .check(matches(isDisplayed()));
    }

    @Test
    public void testBiometricLoginButtonDisplayed() {
        onView(withId(R.id.biometric_login))
                .check(matches(isDisplayed()))
                .check(matches(withText("Login By TouchID or FaceID")));
    }
}

