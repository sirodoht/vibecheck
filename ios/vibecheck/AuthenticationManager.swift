//
//  AuthenticationManager.swift
//  vibecheck
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI
import Combine

class AuthenticationManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var currentUser: SignInResponse?
    
    static let shared = AuthenticationManager()
    
    private init() {
        // Check if user is already authenticated when app starts
        isAuthenticated = AuthService.shared.isAuthenticated
    }
    
    func signIn(username: String, password: String, completion: @escaping (Result<SignInResponse, AuthError>) -> Void) {
        // Use mock for testing - change to signIn for production
        AuthService.shared.signInMock(username: username, password: password) { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success(let response):
                    self?.isAuthenticated = true
                    self?.currentUser = response
                    completion(.success(response))
                case .failure(let error):
                    self?.isAuthenticated = false
                    self?.currentUser = nil
                    completion(.failure(error))
                }
            }
        }
    }
    
    func signOut() {
        AuthService.shared.signOut()
        isAuthenticated = false
        currentUser = nil
    }
}
