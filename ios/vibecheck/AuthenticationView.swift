//
//  AuthenticationView.swift
//  vibecheck
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

enum AuthenticationMode {
    case login
    case signUp
}

struct AuthenticationView: View {
    @State private var currentMode: AuthenticationMode = .login

    var body: some View {
        NavigationView {
            Group {
                switch currentMode {
                case .login:
                    LoginView(onSignUpTapped: {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            currentMode = .signUp
                        }
                    })
                case .signUp:
                    SignUpView(onSignInTapped: {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            currentMode = .login
                        }
                    })
                }
            }
            .navigationBarHidden(true)
        }
        .navigationViewStyle(StackNavigationViewStyle()) // Ensures proper behavior on iPad
    }
}

#Preview {
    AuthenticationView()
}
