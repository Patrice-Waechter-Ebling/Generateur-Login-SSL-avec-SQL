    CREATE PROCEDURE GetEncryptedLogsByUser
        @Username NVARCHAR(255)
    AS
    BEGIN
        SELECT 
            Id,
            LogTimestamp,
            SaltHex,
            CipherHex,
            Algorithm,
            CreatedAt
        FROM EncryptedLogs
        WHERE Username = @Username
        ORDER BY LogTimestamp ASC;
    END;

    CREATE PROCEDURE InsertEncryptedLog
        @Username NVARCHAR(255),
        @LogTimestamp BIGINT,
        @SaltHex VARBINARY(64),
        @CipherHex VARBINARY(MAX),
        @Algorithm NVARCHAR(32)
    AS
    BEGIN
        INSERT INTO EncryptedLogs (Username, LogTimestamp, SaltHex, CipherHex, Algorithm)
        VALUES (@Username, @LogTimestamp, @SaltHex, @CipherHex, @Algorithm);
    END;
