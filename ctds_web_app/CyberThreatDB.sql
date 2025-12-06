CREATE DATABASE CyberThreatDB;
GO
USE CyberThreatDB;
GO

CREATE TABLE Roles (
    RoleID INT PRIMARY KEY IDENTITY(1,1),
    RoleName NVARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL, 
    RoleID INT FOREIGN KEY REFERENCES Roles(RoleID)
);

CREATE TABLE Threats (
    ThreatID INT PRIMARY KEY IDENTITY(1,1),
    ThreatType NVARCHAR(100) NOT NULL, 
    Severity NVARCHAR(20) CHECK (Severity IN ('Low', 'Medium', 'High', 'Critical')),
    Description NVARCHAR(500),
    DetectedDate DATETIME DEFAULT GETDATE()
);

CREATE TABLE Logs (
    LogID INT PRIMARY KEY IDENTITY(1,1),
    UserID INT FOREIGN KEY REFERENCES Users(UserID),
    ThreatID INT FOREIGN KEY REFERENCES Threats(ThreatID),
    Action NVARCHAR(100), 
    Timestamp DATETIME DEFAULT GETDATE()
);
GO 

INSERT INTO Roles (RoleName) VALUES ('Admin'), ('Analyst'), ('Viewer');

INSERT INTO Users (Username, PasswordHash, RoleID) VALUES 
('admin', '805bd951772627f3d1a607084df1727c6caad60447c5d73febf7be2d2fe17fd8', 1),  
('analyst1', '805bd951772627f3d1a607084df1727c6caad60447c5d73febf7be2d2fe17fd8', 2),
('viewer1', '805bd951772627f3d1a607084df1727c6caad60447c5d73febf7be2d2fe17fd8', 3);

INSERT INTO Threats (ThreatType, Severity, Description) VALUES 
('Malware', 'High', 'Ransomware detected on network'),
('Phishing', 'Medium', 'Email scam attempt'),
('DDoS', 'Critical', 'Flood attack on server'),
('SQL Injection', 'High', 'Attempted database breach'),
('Trojan', 'Medium', 'Backdoor installed'),
('Spyware', 'Low', 'Keylogger detected'),
('Zero-Day Exploit', 'Critical', 'Unknown vulnerability'),
('Brute Force', 'Medium', 'Password cracking attempt'),
('Man-in-the-Middle', 'High', 'Traffic interception'),
('Insider Threat', 'High', 'Unauthorized access by employee');

INSERT INTO Logs (UserID, ThreatID, Action) VALUES 
(1, 1, 'Detected and Blocked'),
(2, 2, 'Reported'),
(1, 3, 'Mitigated'),
(2, 4, 'Logged'),
(3, 5, 'Monitored'),
(1, 6, 'Quarantined'),
(2, 7, 'Alerted'),
(3, 8, 'Investigated'),
(1, 9, 'Resolved'),
(2, 10, 'Escalated');
GO  

CREATE VIEW AdminView AS
SELECT 
    t.ThreatID, 
    t.ThreatType, 
    t.Severity, 
    t.Description, 
    t.DetectedDate, 
    l.LogID, 
    l.UserID, 
    l.Action, 
    l.Timestamp, 
    u.Username, 
    u.PasswordHash, 
    u.RoleID
FROM Threats t 
JOIN Logs l ON t.ThreatID = l.ThreatID 
JOIN Users u ON l.UserID = u.UserID
WHERE u.RoleID = 1;  -- Full access for Admins
GO

CREATE VIEW AnalystView AS
SELECT t.ThreatID, t.ThreatType, t.Severity, l.Action, l.Timestamp
FROM Threats t JOIN Logs l ON t.ThreatID = l.ThreatID JOIN Users u ON l.UserID = u.UserID
WHERE u.RoleID = 2;  -- Limited to threat details and actions
GO

CREATE VIEW ViewerView AS
SELECT t.ThreatType, t.Severity, l.Timestamp
FROM Threats t JOIN Logs l ON t.ThreatID = l.ThreatID JOIN Users u ON l.UserID = u.UserID
WHERE u.RoleID = 3;  -- Read-only summary
GO

---- QUERIES

SELECT ThreatID, ThreatType, Severity FROM Threats WHERE Severity = 'High';
--- Relational Algebra: π_{ThreatID, ThreatType, Severity}(σ_{Severity='High'}(Threats))

SELECT l.LogID, l.Action, l.Timestamp FROM Logs l WHERE l.UserID = 1;
--- Relational Algebra: π_{LogID, Action, Timestamp}(σ_{UserID=1}(Logs))

SELECT t.ThreatType, l.Action FROM Threats t JOIN Logs l ON t.ThreatID = l.ThreatID;
--- Relational Algebra: π_{ThreatType, Action}(Threats ⋈_{ThreatID} Logs)

SELECT Severity, COUNT(*) AS Count FROM Threats GROUP BY Severity;
--- Relational Algebra: γ_{Severity; COUNT(*)}(Threats) (γ for aggregation)

SELECT * FROM Threats WHERE DetectedDate > '2023-01-01';
--- Relational Algebra: σ_{DetectedDate>'2023-01-01'}(Threats)

SELECT u.Username, r.RoleName FROM Users u JOIN Roles r ON u.RoleID = r.RoleID;
--- Relational Algebra: π_{Username, RoleName}(Users ⋈_{RoleID} Roles)

SELECT t.ThreatType, l.Action FROM Threats t 
JOIN Logs l ON t.ThreatID = l.ThreatID WHERE t.Severity = 'High';
--- Relational Algebra: π_{ThreatType, Action}(σ_{Severity='High'}(Threats ⋈_{ThreatID} Logs))

SELECT TOP 1 * FROM Logs ORDER BY Timestamp DESC;
--- Relational Algebra: τ_{Timestamp DESC}(Logs) (τ for top-k/sorting, implied limit)

SELECT u.Username, COUNT(l.LogID) AS LogCount FROM Users u 
LEFT JOIN Logs l ON u.UserID = l.UserID GROUP BY u.Username;
--- Relational Algebra: γ_{Username; COUNT(LogID)}(Users ⟕_{UserID} Logs) (⟕ for left join)

SELECT u.Username, r.RoleName, COUNT(l.LogID) AS LogCount FROM Users u
JOIN Roles r ON u.RoleID = r.RoleID
LEFT JOIN Logs l ON u.UserID = l.UserID
GROUP BY u.Username, r.RoleName
ORDER BY LogCount DESC;
/* Relational Algebra: π_{Username, RoleName, COUNT(LogID)}(γ_{Username, RoleName;
COUNT(LogID)}(Users ⋈{RoleID} Roles ⟕{UserID} Logs)) followed by τ_{LogCount DESC} 
(⟕ for left join, γ for aggregation, τ for sorting). */

SELECT ThreatType, Severity, COUNT(*) AS ThreatCount
FROM Threats
GROUP BY ThreatType, Severity
ORDER BY ThreatCount DESC;
/* Relational Algebra: γ_{ThreatType, Severity; COUNT(*)}(Threats) 
followed by τ_{ThreatCount DESC} (γ for aggregation, τ for sorting).*/

BEGIN TRANSACTION;
SAVE TRANSACTION BeforeInsert;  --  savepoint

INSERT INTO Threats (ThreatType, Severity, Description) VALUES ('New Threat', 'Medium', 'Test insertion');
INSERT INTO Logs (UserID, ThreatID, Action) VALUES (1, SCOPE_IDENTITY(), 'Inserted'); 

COMMIT TRANSACTION; 

CREATE LOGIN AdminUser WITH PASSWORD = 'StrongPass123!';
CREATE LOGIN AnalystUser WITH PASSWORD = 'StrongPass123!';
CREATE LOGIN ViewerUser WITH PASSWORD = 'StrongPass123!';

USE CyberThreatDB;

CREATE USER AdminUser FOR LOGIN AdminUser;
CREATE USER AnalystUser FOR LOGIN AnalystUser;
CREATE USER ViewerUser FOR LOGIN ViewerUser;

GRANT SELECT ON AdminView TO AdminUser;
GRANT SELECT ON AnalystView TO AnalystUser;
GRANT SELECT ON ViewerView TO ViewerUser;

REVOKE SELECT ON AdminView FROM AnalystUser;  -- Analysts can't access admin view
REVOKE SELECT ON AdminView FROM ViewerUser;   -- Viewers can't access admin view
REVOKE SELECT ON AnalystView FROM ViewerUser; -- Viewers can't access analyst view