package com.example.hsbcapp;

import androidx.test.espresso.Espresso;
import androidx.test.espresso.action.ViewActions;
import androidx.test.espresso.assertion.ViewAssertions;
import androidx.test.espresso.intent.Intents;
import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.ext.junit.rules.ActivityScenarioRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static androidx.test.espresso.intent.Intents.intended;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.matcher.ViewMatchers.withId;

@RunWith(AndroidJUnit4.class)
@LargeTest
public class ImageUploadActivityTest {

    @Rule
    public ActivityScenarioRule<ImageUploadActivity> activityRule =
            new ActivityScenarioRule<>(ImageUploadActivity.class);

    @Before
    public void setUp() {
        // Initialize Intents before each test
        Intents.init();
    }

    @After
    public void tearDown() {
        // Release Intents after each test
        Intents.release();
    }

    @Test
    public void testInitialViewsDisplayed() {
        // Verify all main views are displayed
        Espresso.onView(withId(R.id.add_image_button))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
        Espresso.onView(withId(R.id.selected_image_view))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
        Espresso.onView(withId(R.id.namef))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
        Espresso.onView(withId(R.id.addressf))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
        Espresso.onView(withId(R.id.mobilef))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
    }


    @Test
    public void testFormSubmission() {
        // Input sample data into the form fields
        Espresso.onView(withId(R.id.namef))
                .perform(ViewActions.typeText("John Doe"), ViewActions.closeSoftKeyboard());
        Espresso.onView(withId(R.id.addressf))
                .perform(ViewActions.typeText("123 Main St"), ViewActions.closeSoftKeyboard());
        Espresso.onView(withId(R.id.mobilef))
                .perform(ViewActions.typeText("9876543210"), ViewActions.closeSoftKeyboard());

        // Click the Submit button
        Espresso.onView(withId(R.id.submit_button))
                .perform(ViewActions.click());

        // Verify form data
        Espresso.onView(withId(R.id.namef))
                .check(ViewAssertions.matches(ViewMatchers.withText("John Doe")));
        Espresso.onView(withId(R.id.addressf))
                .check(ViewAssertions.matches(ViewMatchers.withText("123 Main St")));
        Espresso.onView(withId(R.id.mobilef))
                .check(ViewAssertions.matches(ViewMatchers.withText("9876543210")));
    }

    @Test
    public void testViewAllNavigation() {
        // Click the View All button
        Espresso.onView(withId(R.id.view_all_button))
                .perform(ViewActions.click());

        // Verify navigation to TableActivity
        intended(hasComponent(TableActivity.class.getName()));
    }

    @Test
    public void testAddImageButton() {
        // Click the Add Image button
        Espresso.onView(withId(R.id.add_image_button))
                .perform(ViewActions.click());

        // Verify the image selection dialog/view is displayed
        // Note: You might need to adjust this based on your implementation
        // This is just verifying the button is clickable
        Espresso.onView(withId(R.id.add_image_button))
                .check(ViewAssertions.matches(ViewMatchers.isDisplayed()));
    }
}