//
//  FriendsListView.swift
//  vibecheck
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct FriendsListView: View {
    @State private var connections: [Connection] = []
    @State private var isLoading = true
    @State private var errorMessage = ""
    
    // Callback for sign out
    var onSignOut: () -> Void
    
    var body: some View {
        NavigationView {
            VStack {
                if isLoading {
                    VStack(spacing: 20) {
                        ProgressView()
                            .scaleEffect(1.2)
                        Text("Loading friends...")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if !errorMessage.isEmpty {
                    VStack(spacing: 20) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.largeTitle)
                            .foregroundColor(.orange)
                        
                        Text("Oops!")
                            .font(.title2)
                            .fontWeight(.semibold)
                        
                        Text(errorMessage)
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        
                        Button("Try Again") {
                            loadConnections()
                        }
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if connections.isEmpty {
                    VStack(spacing: 20) {
                        Image(systemName: "person.2.slash")
                            .font(.largeTitle)
                            .foregroundColor(.secondary)
                        
                        Text("No Friends Yet")
                            .font(.title2)
                            .fontWeight(.semibold)
                        
                        Text("Start connecting with people to see them here!")
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        
                        Button("Refresh") {
                            loadConnections()
                        }
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(connections) { connection in
                        ConnectionRow(connection: connection)
                    }
                    .refreshable {
                        loadConnections()
                    }
                }
            }
            .navigationTitle("Friends")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button("Refresh") {
                            loadConnections()
                        }
                        Button("Sign Out") {
                            onSignOut()
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
        }
        .onAppear {
            loadConnections()
        }
    }
    
    private func loadConnections() {
        isLoading = true
        errorMessage = ""
        
        // Using production API
        AuthService.shared.fetchConnections { result in
            DispatchQueue.main.async {
                isLoading = false
                
                switch result {
                case .success(let response):
                    connections = response.connections
                case .failure(let error):
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}

struct ConnectionRow: View {
    let connection: Connection
    
    var body: some View {
        HStack(spacing: 12) {
            // Avatar placeholder
            Circle()
                .fill(statusColor.opacity(0.2))
                .frame(width: 50, height: 50)
                .overlay {
                    if let avatarUrl = connection.avatarUrl, !avatarUrl.isEmpty {
                        // In a real app, you'd use AsyncImage or similar
                        Text(String(connection.displayName?.prefix(1) ?? connection.username.prefix(1)).uppercased())
                            .font(.title2)
                            .fontWeight(.semibold)
                            .foregroundColor(statusColor)
                    } else {
                        Text(String(connection.displayName?.prefix(1) ?? connection.username.prefix(1)).uppercased())
                            .font(.title2)
                            .fontWeight(.semibold)
                            .foregroundColor(statusColor)
                    }
                }
            
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(connection.displayName ?? connection.username)
                        .font(.headline)
                        .foregroundColor(.primary)
                    
                    Spacer()
                    
                    // Status indicator
                    HStack(spacing: 4) {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 8, height: 8)
                        
                        Text(statusText)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                
                if connection.displayName != nil {
                    Text("@\(connection.username)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
    
    private var statusColor: Color {
        switch connection.status?.lowercased() {
        case "online":
            return .green
        case "away":
            return .orange
        case "offline":
            return .gray
        default:
            return .gray
        }
    }
    
    private var statusText: String {
        switch connection.status?.lowercased() {
        case "online":
            return "Online"
        case "away":
            return connection.lastSeen ?? "Away"
        case "offline":
            return connection.lastSeen ?? "Offline"
        default:
            return "Unknown"
        }
    }
}

#Preview {
    FriendsListView(onSignOut: {})
}
