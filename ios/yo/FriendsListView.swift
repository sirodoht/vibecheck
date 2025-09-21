//
//  FriendsListView.swift
//  yo
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import SwiftUI

struct FriendsListView: View {
    @State private var connections: [Connection] = []
    @State private var isLoading = true
    @State private var errorMessage = ""
    @State private var showingAddFriend = false
    @State private var acceptingConnectionId: String? = nil
    @State private var rejectingConnectionId: String? = nil

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
                        ConnectionRow(
                            connection: connection,
                            isAccepting: acceptingConnectionId == connection.id,
                            isRejecting: rejectingConnectionId == connection.id,
                            onAcceptConnection: { connectionId in
                                acceptConnection(connectionId: connectionId)
                            },
                            onRejectConnection: { connectionId in
                                rejectConnection(connectionId: connectionId)
                            }
                        )
                    }
                    .refreshable {
                        loadConnections()
                    }
                }
            }
            .navigationTitle("Friends")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        showingAddFriend = true
                    } label: {
                        Image(systemName: "person.badge.plus")
                            .foregroundColor(.blue)
                    }
                }

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
            .sheet(isPresented: $showingAddFriend) {
                AddFriendView()
                    .onDisappear {
                        // Refresh connections when returning from add friend
                        loadConnections()
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

    private func acceptConnection(connectionId: String) {
        acceptingConnectionId = connectionId

        // Using production API
        AuthService.shared.acceptConnectionRequest(connectionId: connectionId) { result in
            DispatchQueue.main.async {
                acceptingConnectionId = nil

                switch result {
                case .success(_):
                    // Refresh connections to show updated status
                    loadConnections()
                case .failure(let error):
                    // Could show error alert here if needed
                    print("Failed to accept connection: \(error.localizedDescription)")
                }
            }
        }
    }

    private func rejectConnection(connectionId: String) {
        rejectingConnectionId = connectionId

        // Using production API
        AuthService.shared.rejectConnectionRequest(connectionId: connectionId) { result in
            DispatchQueue.main.async {
                rejectingConnectionId = nil

                switch result {
                case .success(_):
                    // Remove from local list and refresh connections
                    connections.removeAll { $0.id == connectionId }
                case .failure(let error):
                    // Could show error alert here if needed
                    print("Failed to reject connection: \(error.localizedDescription)")
                }
            }
        }
    }
}

struct ConnectionRow: View {
    let connection: Connection
    let isAccepting: Bool
    let isRejecting: Bool
    let onAcceptConnection: (String) -> Void
    let onRejectConnection: (String) -> Void

    var body: some View {
        HStack(spacing: 12) {
            // Avatar placeholder
            Circle()
                .fill(statusColor.opacity(0.2))
                .frame(width: 50, height: 50)
                .overlay {
                    Text(String(connection.username.prefix(1)).uppercased())
                        .font(.title2)
                        .fontWeight(.semibold)
                        .foregroundColor(statusColor)
                }

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("@\(connection.username)")
                        .font(.headline)
                        .foregroundColor(.primary)

                    Spacer()

                    // Different UI based on connection status and type
                    if connection.connectionStatus?.lowercased() == "pending" {
                        if connection.isIncoming == true {
                            // Send "yo" to incoming friend request
                            Button {
                                onAcceptConnection(connection.id)
                            } label: {
                                if isAccepting {
                                    ProgressView()
                                        .scaleEffect(0.8)
                                        .tint(.white)
                                } else {
                                    Text("Send Yo")
                                        .font(.system(size: 12, weight: .semibold))
                                }
                            }
                            .frame(width: 80, height: 32)
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(16)
                            .disabled(isAccepting || isRejecting)
                        } else {
                            // Outgoing request - show "Request Sent"
                            Text("REQUEST SENT")
                                .font(.caption2)
                                .fontWeight(.semibold)
                                .foregroundColor(.blue)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Color.blue.opacity(0.2))
                                .cornerRadius(4)
                        }
                    } else {
                        // Accepted friend - show status indicator
                        HStack(spacing: 4) {
                            Circle()
                                .fill(statusColor)
                                .frame(width: 8, height: 8)

                            Text(statusText)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
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

#Preview("Connection Row") {
    let apiConnection = APIConnection(
        id: "1",
        user1_id: "other_user",
        user2_id: "current_user",
        other_username: "user4",
        status: "pending",
        initiated_by: "other_user",
        created_at: "2025-09-20T10:00:00Z"
    )

    List {
        ConnectionRow(
            connection: Connection(from: apiConnection, currentUserId: "current_user"),
            isAccepting: false,
            isRejecting: false,
            onAcceptConnection: { _ in },
            onRejectConnection: { _ in }
        )
    }
}
