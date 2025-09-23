//
//  AuthService.swift
//  yo
//
//  Created by Theodore Keloglou on 20/09/2025.
//

import Foundation
import os.log

enum AuthError: Error, LocalizedError {
    case invalidURL
    case noData
    case invalidResponse
    case serverError(String)
    case networkError(String)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid URL"
        case .noData:
            return "No data received"
        case .invalidResponse:
            return "Invalid response from server"
        case .serverError(let message):
            return message
        case .networkError(let message):
            return "Network error: \(message)"
        }
    }
}

struct SignUpRequest: Codable {
    let username: String
    let password: String
}

struct SignUpResponse: Codable {
    // API returns empty object {} for successful registration
}

struct SignInRequest: Codable {
    let username: String
    let password: String
}

struct SignInResponse: Codable {
    let token: String
}

struct APIConnection: Codable {
    let initiator: String
    let other: String
    let status: String // pending, accepted
    let created_at: String
}

struct Connection: Codable, Identifiable {
    let id: String // Use username as ID for simplicity
    let username: String
    let displayName: String?
    let avatarUrl: String?
    let status: String? // online, offline, away (for display)
    let lastSeen: String?
    let connectionStatus: String? // pending, accepted
    let isIncoming: Bool? // true if this is an incoming request, false if outgoing

    // Convert from API response
    init(from apiConnection: APIConnection, currentUsername: String) {
        self.username = apiConnection.other
        self.id = apiConnection.other // Use username as ID
        self.displayName = nil // Don't show display name, only username with @
        self.avatarUrl = nil
        
        // For now, don't show online status since API doesn't provide it
        self.status = "offline"
        self.lastSeen = nil
        
        self.connectionStatus = apiConnection.status
        self.isIncoming = apiConnection.initiator != currentUsername
    }
}

struct APIConnectionsResponse: Codable {
    let connections: [APIConnection]
}

struct ConnectionsResponse: Codable {
    let connections: [Connection]
}

struct ConnectionRequest: Codable {
    let username: String
}

struct ConnectionRequestResponse: Codable {
    // API returns empty object {} for successful connection request
}

struct AcceptConnectionRequest: Codable {
    let username: String
}

struct AcceptConnectionResponse: Codable {
    // API returns empty object {} for successful accept
}

struct RejectConnectionRequest: Codable {
    let username: String
}

struct RejectConnectionResponse: Codable {
    // API returns empty object {} for successful reject (if endpoint exists)
}

class AuthService {
    static let shared = AuthService()

    // Logger for debugging
    private let logger = Logger(subsystem: "com.yo.app", category: "AuthService")

    // Update this URL to your actual API endpoint
    private let baseURL = "https://yoapi.01z.io/api"

    // Store authentication token and current username
    private var authToken: String?
    private var currentUsername: String?

    private init() {}

    func signUp(username: String, password: String, completion: @escaping (Result<SignUpResponse, AuthError>) -> Void) {
        logger.info("🚀 Starting sign up request for username: \(username)")

        guard let url = URL(string: "\(baseURL)/register") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/register")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let signUpRequest = SignUpRequest(username: username, password: password)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        do {
            let requestBody = try JSONEncoder().encode(signUpRequest)
            request.httpBody = requestBody

            if let bodyString = String(data: requestBody, encoding: .utf8) {
                logger.info("📤 Request body: \(bodyString)")
            }
        } catch {
            logger.error("❌ Failed to encode request: \(error.localizedDescription)")
            completion(.failure(.networkError("Failed to encode request")))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                // API returns empty object {} for successful registration
                self.logger.info("🎉 Sign up successful!")
                let signUpResponse = SignUpResponse()
                completion(.success(signUpResponse))
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Sign up failed")))
                }
            }
        }.resume()
    }

    func signIn(username: String, password: String, completion: @escaping (Result<SignInResponse, AuthError>) -> Void) {
        logger.info("🔐 Starting sign in request for username: \(username)")

        guard let url = URL(string: "\(baseURL)/login") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/login")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let signInRequest = SignInRequest(username: username, password: password)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        do {
            let requestBody = try JSONEncoder().encode(signInRequest)
            request.httpBody = requestBody

            if let bodyString = String(data: requestBody, encoding: .utf8) {
                logger.info("📤 Request body: \(bodyString)")
            }
        } catch {
            logger.error("❌ Failed to encode request: \(error.localizedDescription)")
            completion(.failure(.networkError("Failed to encode request")))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                do {
                    let signInResponse = try JSONDecoder().decode(SignInResponse.self, from: data)
                    self.logger.info("✅ Successfully decoded response with token")
                    
                    self.logger.info("🎉 Sign in successful!")
                    // Store auth token and username for future API calls
                    self.authToken = signInResponse.token
                    self.currentUsername = username // Store the username we used to sign in
                    self.logger.info("🔑 Auth token stored")
                    self.logger.info("👤 Username stored: \(username)")
                    
                    completion(.success(signInResponse))
                } catch {
                    self.logger.error("❌ Failed to decode successful response: \(error.localizedDescription)")
                    completion(.failure(.invalidResponse))
                }
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Sign in failed")))
                }
            }
        }.resume()
    }

    func fetchConnections(completion: @escaping (Result<ConnectionsResponse, AuthError>) -> Void) {
        logger.info("👥 Starting fetch connections request")

        guard let url = URL(string: "\(baseURL)/connections") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        // Add authorization header if we have a token
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            logger.info("🔑 Added auth token to request")
        } else {
            logger.warning("⚠️ No auth token available")
        }

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                do {
                    let apiResponse = try JSONDecoder().decode(APIConnectionsResponse.self, from: data)
                    self.logger.info("✅ Successfully decoded response, connections count=\(apiResponse.connections.count)")
                    
                    self.logger.info("🎉 Connections fetched successfully!")
                    
                    // Convert API connections to our Connection model
                    let username = self.currentUsername ?? ""
                    let connections = apiResponse.connections.map { apiConnection in
                        Connection(from: apiConnection, currentUsername: username)
                    }
                    
                    let connectionsResponse = ConnectionsResponse(connections: connections)
                    completion(.success(connectionsResponse))
                } catch {
                    self.logger.error("❌ Failed to decode successful response: \(error.localizedDescription)")
                    completion(.failure(.invalidResponse))
                }
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Failed to fetch connections")))
                }
            }
        }.resume()
    }

    // Add logout functionality
    func signOut() {
        logger.info("🚪 Signing out user")
        authToken = nil
        currentUsername = nil
    }

    // Check if user is authenticated
    var isAuthenticated: Bool {
        return authToken != nil
    }

    func sendConnectionRequest(to username: String, completion: @escaping (Result<ConnectionRequestResponse, AuthError>) -> Void) {
        logger.info("📤 Starting connection request to username: \(username)")

        guard let url = URL(string: "\(baseURL)/connections/request") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections/request")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let connectionRequest = ConnectionRequest(username: username)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        // Add authorization header if we have a token
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            logger.info("🔑 Added auth token to request")
        } else {
            logger.warning("⚠️ No auth token available")
            completion(.failure(.serverError("Not authenticated")))
            return
        }

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        do {
            let requestBody = try JSONEncoder().encode(connectionRequest)
            request.httpBody = requestBody

            if let bodyString = String(data: requestBody, encoding: .utf8) {
                logger.info("📤 Request body: \(bodyString)")
            }
        } catch {
            logger.error("❌ Failed to encode request: \(error.localizedDescription)")
            completion(.failure(.networkError("Failed to encode request")))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                // API returns empty object {} for successful connection request
                self.logger.info("🎉 Connection request sent successfully!")
                let connectionResponse = ConnectionRequestResponse()
                completion(.success(connectionResponse))
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Failed to send connection request")))
                }
            }
        }.resume()
    }

    func acceptConnectionRequest(username: String, completion: @escaping (Result<AcceptConnectionResponse, AuthError>) -> Void) {
        logger.info("✅ Starting accept connection request from: \(username)")

        guard let url = URL(string: "\(baseURL)/connections/accept") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections/accept")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let acceptRequest = AcceptConnectionRequest(username: username)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        // Add authorization header if we have a token
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            logger.info("🔑 Added auth token to request")
        } else {
            logger.warning("⚠️ No auth token available")
            completion(.failure(.serverError("Not authenticated")))
            return
        }

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        do {
            let requestBody = try JSONEncoder().encode(acceptRequest)
            request.httpBody = requestBody

            if let bodyString = String(data: requestBody, encoding: .utf8) {
                logger.info("📤 Request body: \(bodyString)")
            }
        } catch {
            logger.error("❌ Failed to encode request: \(error.localizedDescription)")
            completion(.failure(.networkError("Failed to encode request")))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                // API returns empty object {} for successful accept
                self.logger.info("🎉 Connection request accepted successfully!")
                let acceptResponse = AcceptConnectionResponse()
                completion(.success(acceptResponse))
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Failed to accept connection request")))
                }
            }
        }.resume()
    }

    func rejectConnectionRequest(username: String, completion: @escaping (Result<RejectConnectionResponse, AuthError>) -> Void) {
        logger.info("❌ Starting reject connection request from: \(username)")

        guard let url = URL(string: "\(baseURL)/connections/reject") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections/reject")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let rejectRequest = RejectConnectionRequest(username: username)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "ngrok-skip-browser-warning") // For ngrok

        // Add authorization header if we have a token
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            logger.info("🔑 Added auth token to request")
        } else {
            logger.warning("⚠️ No auth token available")
            completion(.failure(.serverError("Not authenticated")))
            return
        }

        logger.info("📝 Request headers: \(request.allHTTPHeaderFields ?? [:])")

        do {
            let requestBody = try JSONEncoder().encode(rejectRequest)
            request.httpBody = requestBody

            if let bodyString = String(data: requestBody, encoding: .utf8) {
                logger.info("📤 Request body: \(bodyString)")
            }
        } catch {
            logger.error("❌ Failed to encode request: \(error.localizedDescription)")
            completion(.failure(.networkError("Failed to encode request")))
            return
        }

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.logger.error("❌ Network error: \(error.localizedDescription)")
                completion(.failure(.networkError(error.localizedDescription)))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.logger.error("❌ Invalid HTTP response")
                completion(.failure(.invalidResponse))
                return
            }

            self.logger.info("📥 Response status code: \(httpResponse.statusCode)")
            self.logger.info("📋 Response headers: \(httpResponse.allHeaderFields)")

            guard let data = data else {
                self.logger.error("❌ No data in response")
                completion(.failure(.noData))
                return
            }

            // Log raw response data
            if let responseString = String(data: data, encoding: .utf8) {
                self.logger.info("📄 Raw response: \(responseString)")
            }

            if httpResponse.statusCode == 200 {
                // API returns empty object {} for successful reject
                self.logger.info("🎉 Connection request rejected successfully!")
                let rejectResponse = RejectConnectionResponse()
                completion(.success(rejectResponse))
            } else {
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["error"] as? String {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): Unknown error")
                    completion(.failure(.serverError("Failed to reject connection request")))
                }
            }
        }.resume()
    }

    // For development/testing - simulate API call
    func signUpMock(username: String, password: String, completion: @escaping (Result<SignUpResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
            // Simulate some validation
            if username.isEmpty {
                completion(.failure(.serverError("Username is required")))
                return
            }

            if password.count < 6 {
                completion(.failure(.serverError("Password must be at least 6 characters")))
                return
            }

            // Simulate username already exists
            if username.lowercased() == "admin" {
                completion(.failure(.serverError("Username already exists")))
                return
            }

            // Success case
            let response = SignUpResponse()
            completion(.success(response))
        }
    }

    // For development/testing - simulate sign in API call
    func signInMock(username: String, password: String, completion: @escaping (Result<SignInResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            // Simulate some validation
            if username.isEmpty {
                completion(.failure(.serverError("Username is required")))
                return
            }

            if password.isEmpty {
                completion(.failure(.serverError("Password is required")))
                return
            }

            // Simulate invalid credentials
            if username.lowercased() == "wronguser" || password == "wrongpass" {
                completion(.failure(.serverError("Invalid username or password")))
                return
            }

            // Success case
            let response = SignInResponse(
                token: "mock_jwt_token_\(UUID().uuidString)"
            )
            // Store mock token and username
            self.authToken = response.token
            self.currentUsername = username
            completion(.success(response))
        }
    }

    // For development/testing - simulate connections API call
    func fetchConnectionsMock(completion: @escaping (Result<ConnectionsResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Mock connections data using new structure
            let username = self.currentUsername ?? "mock_user"
            let mockApiConnections = [
                APIConnection(
                    initiator: "alice",
                    other: "alice",
                    status: "accepted",
                    created_at: "2025-09-20T10:00:00Z"
                ),
                APIConnection(
                    initiator: username,
                    other: "bob",
                    status: "accepted",
                    created_at: "2025-09-19T15:30:00Z"
                ),
                APIConnection(
                    initiator: "charlie",
                    other: "charlie",
                    status: "pending",
                    created_at: "2025-09-20T16:00:00Z"
                ),
                APIConnection(
                    initiator: "eve",
                    other: "eve",
                    status: "pending",
                    created_at: "2025-09-20T14:00:00Z"
                ),
                APIConnection(
                    initiator: username,
                    other: "frank",
                    status: "pending",
                    created_at: "2025-09-20T12:00:00Z"
                )
            ]

            // Convert to Connection objects
            let mockConnections = mockApiConnections.map { apiConnection in
                Connection(from: apiConnection, currentUsername: username)
            }

            let response = ConnectionsResponse(connections: mockConnections)
            completion(.success(response))
        }
    }

    // For development/testing - simulate connection request API call
    func sendConnectionRequestMock(to username: String, completion: @escaping (Result<ConnectionRequestResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Validate username
            let trimmedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedUsername.isEmpty {
                completion(.failure(.serverError("Username is required")))
                return
            }

            // Simulate various scenarios
            switch trimmedUsername.lowercased() {
            case "nonexistent", "notfound":
                completion(.failure(.serverError("User not found")))
                return
            case "self", "me":
                completion(.failure(.serverError("You cannot send a friend request to yourself")))
                return
            case "alreadyfriend":
                completion(.failure(.serverError("You are already friends with this user")))
                return
            case "pending":
                completion(.failure(.serverError("Friend request already pending")))
                return
            default:
                break
            }

            // Success case
            let response = ConnectionRequestResponse()
            completion(.success(response))
        }
    }

    // For development/testing - simulate accept connection request API call
    func acceptConnectionRequestMock(username: String, completion: @escaping (Result<AcceptConnectionResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Validate username
            if username.isEmpty {
                completion(.failure(.serverError("Username is required")))
                return
            }

            // Simulate various scenarios
            switch username.lowercased() {
            case "invalid_user":
                completion(.failure(.serverError("User not found")))
                return
            case "already_accepted":
                completion(.failure(.serverError("Connection request already accepted")))
                return
            case "expired":
                completion(.failure(.serverError("Connection request has expired")))
                return
            default:
                break
            }

            // Success case
            let response = AcceptConnectionResponse()
            completion(.success(response))
        }
    }

    // For development/testing - simulate reject connection request API call
    func rejectConnectionRequestMock(username: String, completion: @escaping (Result<RejectConnectionResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Validate username
            if username.isEmpty {
                completion(.failure(.serverError("Username is required")))
                return
            }

            // Simulate various scenarios
            switch username.lowercased() {
            case "invalid_user":
                completion(.failure(.serverError("User not found")))
                return
            case "already_rejected":
                completion(.failure(.serverError("Connection request already rejected")))
                return
            case "expired":
                completion(.failure(.serverError("Connection request has expired")))
                return
            default:
                break
            }

            // Success case
            let response = RejectConnectionResponse()
            completion(.success(response))
        }
    }
}
