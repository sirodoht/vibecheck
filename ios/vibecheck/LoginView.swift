//
//  LoginView.swift
//  vibecheck
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct LoginView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var isLoading = false
    @State private var errorMessage = ""

    // Navigation callback
    var onSignUpTapped: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            // App title or logo area
            VStack(spacing: 8) {
                Image(systemName: "person.circle")
                    .resizable()
                    .frame(width: 80, height: 80)
                    .foregroundColor(.blue)

                Text("Vibecheck")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Sign in to your account")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
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
            }
            .padding(.horizontal)

            // Error message
            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }

            // Sign in button
            Button(action: signIn) {
                HStack {
                    if isLoading {
                        ProgressView()
                            .scaleEffect(0.8)
                            .foregroundColor(.white)
                    }
                    Text(isLoading ? "Signing In..." : "Sign In")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(isFormValid ? Color.blue : Color.gray)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
            .disabled(!isFormValid || isLoading)
            .padding(.horizontal)

            // Forgot password (placeholder)
            Button("Forgot Password?") {
                // Handle forgot password
            }
            .font(.footnote)
            .foregroundColor(.blue)

            Spacer()

            // Sign up link
            HStack {
                Text("Don't have an account?")
                    .foregroundColor(.secondary)
                Button("Sign Up") {
                    onSignUpTapped()
                }
            }
            .font(.footnote)

            Spacer()
        }
    }

    private var isFormValid: Bool {
        !username.isEmpty && !password.isEmpty
    }

    private func signIn() {
        clearError()

        guard isFormValid else {
            setError("Please fill in all fields")
            return
        }

        isLoading = true

        // Call API
        AuthenticationManager.shared.signIn(username: username, password: password) { result in
            isLoading = false
            
            switch result {
            case .success:
                // Clear form - user will automatically navigate to friends list
                username = ""
                password = ""
            case .failure(let error):
                setError(error.localizedDescription)
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
    LoginView(onSignUpTapped: {})
}
