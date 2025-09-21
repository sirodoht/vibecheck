//
//  ContentView.swift
//  yo
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var authManager = AuthenticationManager.shared

    var body: some View {
        Group {
            if authManager.isAuthenticated {
                FriendsListView(onSignOut: {
                    authManager.signOut()
                })
            } else {
                AuthenticationView()
            }
        }
    }
}

#Preview {
    ContentView()
}
