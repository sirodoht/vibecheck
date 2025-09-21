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
    let success: Bool
    let message: String?
    let userId: String?
}

struct SignInRequest: Codable {
    let username: String
    let password: String
}

struct SignInResponse: Codable {
    let success: Bool
    let message: String?
    let userId: String?
    let token: String?
}

struct APIConnection: Codable {
    let id: String
    let user1_id: String
    let user2_id: String
    let other_username: String
    let status: String // pending, accepted, rejected
    let initiated_by: String
    let created_at: String
}

struct Connection: Codable, Identifiable {
    let id: String // This will be the connection ID
    let username: String
    let displayName: String?
    let avatarUrl: String?
    let status: String? // online, offline, away (for display)
    let lastSeen: String?
    let connectionStatus: String? // pending, accepted, rejected
    let isIncoming: Bool? // true if this is an incoming request, false if outgoing

    // Convert from API response
    init(from apiConnection: APIConnection, currentUserId: String) {
        self.id = apiConnection.id
        self.username = apiConnection.other_username
        self.displayName = nil // Don't show display name, only username with @

        self.avatarUrl = nil

        // For now, don't show online status since API doesn't provide it
        self.status = "offline"
        self.lastSeen = nil

        self.connectionStatus = apiConnection.status
        self.isIncoming = apiConnection.initiated_by != currentUserId
    }
}

struct APIConnectionsResponse: Codable {
    let success: Bool
    let connections: [APIConnection]
    let message: String?
}

struct ConnectionsResponse: Codable {
    let success: Bool
    let connections: [Connection]
    let message: String?
}

struct ConnectionRequest: Codable {
    let username: String
}

struct ConnectionRequestResponse: Codable {
    let success: Bool
    let message: String?
    let connection_id: String?
}

struct AcceptConnectionRequest: Codable {
    let connection_id: String
}

struct AcceptConnectionResponse: Codable {
    let success: Bool
    let message: String?
}

struct RejectConnectionRequest: Codable {
    let connection_id: String
}

struct RejectConnectionResponse: Codable {
    let success: Bool
    let message: String?
}

class AuthService {
    static let shared = AuthService()

    // Logger for debugging
    private let logger = Logger(subsystem: "com.yo.app", category: "AuthService")

    // Update this URL to your actual API endpoint
    private let baseURL = "https://yoapi.01z.io/api"

    // Store authentication token and user ID
    private var authToken: String?
    private var currentUserId: String?

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

            do {
                let signUpResponse = try JSONDecoder().decode(SignUpResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(signUpResponse.success), message=\(signUpResponse.message ?? "nil")")

                if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                    self.logger.info("🎉 Sign up successful!")
                    completion(.success(signUpResponse))
                } else {
                    let errorMessage = signUpResponse.message ?? "Sign up failed"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response - check for both "message" and "error" fields
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    let errorMessage = errorDict["message"] as? String ?? errorDict["error"] as? String
                    if let errorMessage = errorMessage {
                        self.logger.info("📝 Parsed error message: \(errorMessage)")
                        completion(.failure(.serverError(errorMessage)))
                    } else {
                        self.logger.error("❌ No error message found in response")
                        completion(.failure(.invalidResponse))
                    }
                } else {
                    completion(.failure(.invalidResponse))
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

            do {
                let signInResponse = try JSONDecoder().decode(SignInResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(signInResponse.success), message=\(signInResponse.message ?? "nil")")

                if httpResponse.statusCode == 200 {
                    self.logger.info("🎉 Sign in successful!")
                    // Store auth token and user ID for future API calls
                    if let token = signInResponse.token {
                        self.authToken = token
                        self.logger.info("🔑 Auth token stored")
                    }
                    if let userId = signInResponse.userId {
                        self.currentUserId = userId
                        self.logger.info("👤 User ID stored: \(userId)")
                    }
                    completion(.success(signInResponse))
                } else {
                    let errorMessage = signInResponse.message ?? "Sign in failed"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response - check for both "message" and "error" fields
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    let errorMessage = errorDict["message"] as? String ?? errorDict["error"] as? String
                    if let errorMessage = errorMessage {
                        self.logger.info("📝 Parsed error message: \(errorMessage)")
                        completion(.failure(.serverError(errorMessage)))
                    } else {
                        self.logger.error("❌ No error message found in response")
                        completion(.failure(.invalidResponse))
                    }
                } else {
                    completion(.failure(.invalidResponse))
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

            do {
                let apiResponse = try JSONDecoder().decode(APIConnectionsResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(apiResponse.success), connections count=\(apiResponse.connections.count)")

                if httpResponse.statusCode == 200 {
                    self.logger.info("🎉 Connections fetched successfully!")

                    // Convert API connections to our Connection model
                    let userId = self.currentUserId ?? ""
                    let connections = apiResponse.connections.map { apiConnection in
                        Connection(from: apiConnection, currentUserId: userId)
                    }

                    let connectionsResponse = ConnectionsResponse(
                        success: apiResponse.success,
                        connections: connections,
                        message: apiResponse.message
                    )

                    completion(.success(connectionsResponse))
                } else {
                    let errorMessage = apiResponse.message ?? "Failed to fetch connections"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["message"] as? String {
                    self.logger.info("📝 Parsed error message: \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    completion(.failure(.invalidResponse))
                }
            }
        }.resume()
    }

    // Add logout functionality
    func signOut() {
        logger.info("🚪 Signing out user")
        authToken = nil
        currentUserId = nil
    }

    // Check if user is authenticated
    var isAuthenticated: Bool {
        return authToken != nil
    }

    func sendConnectionRequest(to username: String, completion: @escaping (Result<ConnectionRequestResponse, AuthError>) -> Void) {
        logger.info("📤 Starting connection request to username: \(username)")

        guard let url = URL(string: "\(baseURL)/connections") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections")
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

            do {
                let connectionResponse = try JSONDecoder().decode(ConnectionRequestResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(connectionResponse.success), message=\(connectionResponse.message ?? "nil")")

                if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                    self.logger.info("🎉 Connection request sent successfully!")
                    completion(.success(connectionResponse))
                } else {
                    let errorMessage = connectionResponse.message ?? "Failed to send connection request"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response - check for both "message" and "error" fields
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    let errorMessage = errorDict["message"] as? String ?? errorDict["error"] as? String
                    if let errorMessage = errorMessage {
                        self.logger.info("📝 Parsed error message: \(errorMessage)")
                        completion(.failure(.serverError(errorMessage)))
                    } else {
                        self.logger.error("❌ No error message found in response")
                        completion(.failure(.invalidResponse))
                    }
                } else {
                    completion(.failure(.invalidResponse))
                }
            }
        }.resume()
    }

    func acceptConnectionRequest(connectionId: String, completion: @escaping (Result<AcceptConnectionResponse, AuthError>) -> Void) {
        logger.info("✅ Starting accept connection request: \(connectionId)")

        guard let url = URL(string: "\(baseURL)/connections/accept") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections/accept")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let acceptRequest = AcceptConnectionRequest(connection_id: connectionId)

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

            do {
                let acceptResponse = try JSONDecoder().decode(AcceptConnectionResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(acceptResponse.success), message=\(acceptResponse.message ?? "nil")")

                if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                    self.logger.info("🎉 Connection request accepted successfully!")
                    completion(.success(acceptResponse))
                } else {
                    let errorMessage = acceptResponse.message ?? "Failed to accept connection request"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["message"] as? String {
                    self.logger.info("📝 Parsed error message: \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    completion(.failure(.invalidResponse))
                }
            }
        }.resume()
    }

    func rejectConnectionRequest(connectionId: String, completion: @escaping (Result<RejectConnectionResponse, AuthError>) -> Void) {
        logger.info("❌ Starting reject connection request: \(connectionId)")

        guard let url = URL(string: "\(baseURL)/connections/reject") else {
            logger.error("❌ Invalid URL: \(self.baseURL)/connections/reject")
            completion(.failure(.invalidURL))
            return
        }

        logger.info("📡 Making request to: \(url.absoluteString)")

        let rejectRequest = RejectConnectionRequest(connection_id: connectionId)

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

            do {
                let rejectResponse = try JSONDecoder().decode(RejectConnectionResponse.self, from: data)
                self.logger.info("✅ Successfully decoded response: success=\(rejectResponse.success), message=\(rejectResponse.message ?? "nil")")

                if httpResponse.statusCode == 200 || httpResponse.statusCode == 201 {
                    self.logger.info("🎉 Connection request rejected successfully!")
                    completion(.success(rejectResponse))
                } else {
                    let errorMessage = rejectResponse.message ?? "Failed to reject connection request"
                    self.logger.error("❌ Server error (\(httpResponse.statusCode)): \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                }
            } catch {
                self.logger.error("❌ Failed to decode response: \(error.localizedDescription)")
                // Try to parse error response
                if let errorDict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let errorMessage = errorDict["message"] as? String {
                    self.logger.info("📝 Parsed error message: \(errorMessage)")
                    completion(.failure(.serverError(errorMessage)))
                } else {
                    completion(.failure(.invalidResponse))
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
            let response = SignUpResponse(
                success: true,
                message: "Account created successfully",
                userId: UUID().uuidString
            )
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
                success: true,
                message: "Sign in successful",
                userId: UUID().uuidString,
                token: "mock_jwt_token_\(UUID().uuidString)"
            )
            // Store mock token and user ID
            self.authToken = response.token
            self.currentUserId = response.userId
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
            let userId = self.currentUserId ?? "mock_user_id"
            let mockApiConnections = [
                APIConnection(
                    id: "1",
                    user1_id: userId,
                    user2_id: "alice_id",
                    other_username: "alice",
                    status: "accepted",
                    initiated_by: "alice_id",
                    created_at: "2025-09-20T10:00:00Z"
                ),
                APIConnection(
                    id: "2",
                    user1_id: userId,
                    user2_id: "bob_id",
                    other_username: "bob",
                    status: "accepted",
                    initiated_by: userId,
                    created_at: "2025-09-19T15:30:00Z"
                ),
                APIConnection(
                    id: "3",
                    user1_id: "charlie_id",
                    user2_id: userId,
                    other_username: "charlie",
                    status: "pending",
                    initiated_by: "charlie_id",
                    created_at: "2025-09-20T16:00:00Z"
                ),
                APIConnection(
                    id: "4",
                    user1_id: userId,
                    user2_id: "eve_id",
                    other_username: "eve",
                    status: "pending",
                    initiated_by: "eve_id",
                    created_at: "2025-09-20T14:00:00Z"
                ),
                APIConnection(
                    id: "5",
                    user1_id: userId,
                    user2_id: "frank_id",
                    other_username: "frank",
                    status: "pending",
                    initiated_by: userId,
                    created_at: "2025-09-20T12:00:00Z"
                )
            ]

            // Convert to Connection objects
            let mockConnections = mockApiConnections.map { apiConnection in
                Connection(from: apiConnection, currentUserId: userId)
            }

            let response = ConnectionsResponse(
                success: true,
                connections: mockConnections,
                message: "Connections retrieved successfully"
            )
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
            let response = ConnectionRequestResponse(
                success: true,
                message: "Friend request sent to \(trimmedUsername)!",
                connection_id: UUID().uuidString
            )
            completion(.success(response))
        }
    }

    // For development/testing - simulate accept connection request API call
    func acceptConnectionRequestMock(connectionId: String, completion: @escaping (Result<AcceptConnectionResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Validate connection ID
            if connectionId.isEmpty {
                completion(.failure(.serverError("Connection ID is required")))
                return
            }

            // Simulate various scenarios
            switch connectionId {
            case "invalid_id":
                completion(.failure(.serverError("Invalid connection ID")))
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
            let response = AcceptConnectionResponse(
                success: true,
                message: "Friend request accepted successfully!"
            )
            completion(.success(response))
        }
    }

    // For development/testing - simulate reject connection request API call
    func rejectConnectionRequestMock(connectionId: String, completion: @escaping (Result<RejectConnectionResponse, AuthError>) -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.8) {
            // Check if authenticated
            guard self.authToken != nil else {
                completion(.failure(.serverError("Not authenticated")))
                return
            }

            // Validate connection ID
            if connectionId.isEmpty {
                completion(.failure(.serverError("Connection ID is required")))
                return
            }

            // Simulate various scenarios
            switch connectionId {
            case "invalid_id":
                completion(.failure(.serverError("Invalid connection ID")))
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
            let response = RejectConnectionResponse(
                success: true,
                message: "Friend request rejected successfully!"
            )
            completion(.success(response))
        }
    }
}
