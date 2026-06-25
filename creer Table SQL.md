use [DemoLogsDB]
CREATE TABLE EncryptedLogs (
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    Username      NVARCHAR(255) NOT NULL,
    LogTimestamp  BIGINT        NOT NULL,
    SaltHex       VARBINARY(64) NOT NULL,
    CipherHex     VARBINARY(MAX) NOT NULL,
    Algorithm     NVARCHAR(32) NOT NULL DEFAULT 'MSE2026',
    CreatedAt     DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
