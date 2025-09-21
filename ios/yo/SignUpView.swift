//
//  SignUpView.swift
//  yo
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct SignUpView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingSuccessAlert = false

    // Navigation callback
    var onSignInTapped: (() -> Void)? = nil

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Spacer()

                // App title or logo area
                VStack(spacing: 8) {
                    Image(systemName: "person.circle.fill")
                        .resizable()
                        .frame(width: 80, height: 80)
                        .foregroundColor(.blue)

                    Text("Create Account")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                }

                Spacer()

                // Form fields
                VStack(spacing: 16) {
                    TextField("Username", text: $username)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    SecureField("Password", text: $password)
                        .textFieldStyle(RoundedBorderTextFieldStyle())

                    SecureField("Confirm Password", text: $confirmPassword)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                }
                .padding(.horizontal)

                // Error message
                if !errorMessage.isEmpty {
                    Text(errorMessage)
                        .foregroundColor(.red)
                        .font(.caption)
                        .padding(.horizontal)
                }

                // Sign up button
                Button(action: signUp) {
                    HStack {
                        if isLoading {
                            ProgressView()
                                .scaleEffect(0.8)
                                .foregroundColor(.white)
                        }
                        Text(isLoading ? "Creating Account..." : "Sign Up")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(isFormValid ? Color.blue : Color.gray)
                    .foregroundColor(.white)
                    .cornerRadius(10)
                }
                .disabled(!isFormValid || isLoading)
                .padding(.horizontal)

                Spacer()

                // Sign in link
                HStack {
                    Text("Already have an account?")
                        .foregroundColor(.secondary)
                    Button("Sign In") {
                        onSignInTapped?()
                    }
                }
                .font(.footnote)

                Spacer()
            }
            .navigationBarHidden(true)
        }
        .alert("Success!", isPresented: $showingSuccessAlert) {
            Button("OK") { }
        } message: {
            Text("Account created successfully!")
        }
    }

    private var isFormValid: Bool {
        !username.isEmpty &&
        !password.isEmpty &&
        !confirmPassword.isEmpty &&
        password == confirmPassword &&
        password.count >= 6
    }

    private func signUp() {
        clearError()

        // Validation
        guard isFormValid else {
            if password != confirmPassword {
                setError("Passwords don't match")
            } else if password.count < 6 {
                setError("Password must be at least 6 characters")
            } else {
                setError("Please fill in all fields")
            }
            return
        }

        isLoading = true

        // Call API
        AuthService.shared.signUp(username: username, password: password) { result in
            DispatchQueue.main.async {
                isLoading = false

                switch result {
                case .success:
                    showingSuccessAlert = true
                    // Clear form
                    username = ""
                    password = ""
                    confirmPassword = ""
                case .failure(let error):
                    setError(error.localizedDescription)
                }
            }
        }
    }

    private func setError(_ message: String) {
        errorMessage = message
    }

    private func clearError() {
        errorMessage = ""
    }
}

#Preview {
    SignUpView(onSignInTapped: {})
}
