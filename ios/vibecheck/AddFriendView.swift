//
//  AddFriendView.swift
//  vibecheck
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct AddFriendView: View {
    @State private var username = ""
    @State private var isLoading = false
    @State private var errorMessage = ""
    @State private var showingSuccessAlert = false
    @State private var successMessage = ""

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Spacer()

                // Header
                VStack(spacing: 8) {
                    Image(systemName: "person.badge.plus")
                        .resizable()
                        .frame(width: 60, height: 60)
                        .foregroundColor(.blue)

                    Text("Add Friend")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Enter a username to send a friend request")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()

                // Username input
                VStack(spacing: 16) {
                    TextField("Username", text: $username)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .font(.body)
                        .padding(.horizontal)

                    // Error message
                    if !errorMessage.isEmpty {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text(errorMessage)
                                .foregroundColor(.red)
                                .font(.caption)
                            Spacer()
                        }
                        .padding(.horizontal)
                    }

                    // Send request button
                    Button(action: sendConnectionRequest) {
                        HStack {
                            if isLoading {
                                ProgressView()
                                    .scaleEffect(0.8)
                                    .foregroundColor(.white)
                            }
                            Text(isLoading ? "Sending..." : "Send Friend Request")
                        }
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(isFormValid && !isLoading ? Color.blue : Color.gray)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                    }
                    .disabled(!isFormValid || isLoading)
                    .padding(.horizontal)
                }

                Spacer()
                Spacer()
            }
            .navigationTitle("Add Friend")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
        .alert("Success!", isPresented: $showingSuccessAlert) {
            Button("OK") {
                dismiss()
            }
        } message: {
            Text(successMessage)
        }
    }

    private var isFormValid: Bool {
        !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func sendConnectionRequest() {
        let trimmedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)

        guard isFormValid else {
            setError("Please enter a username")
            return
        }

        clearError()
        isLoading = true

        // Using production API
        AuthService.shared.sendConnectionRequest(to: trimmedUsername) { result in
            DispatchQueue.main.async {
                isLoading = false

                switch result {
                case .success(let response):
                    successMessage = response.message ?? "Friend request sent successfully!"
                    showingSuccessAlert = true
                    username = "" // Clear the field

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
    AddFriendView()
}
