USE [master]
GO
CREATE DATABASE [sasDB]
GO
USE sasDB

CREATE TABLE [User] (
	[UserID] [int] PRIMARY KEY IDENTITY(1,1),
    [Username] [varchar](32),
	[Password] [varchar](32),
	[Email] [nvarchar](320),
	[Role] [int]
);

CREATE TABLE [Admin] (
	[AdminID] [int] PRIMARY KEY FOREIGN KEY REFERENCES [User](UserID) NOT NULL,
    [Name] [nvarchar](50)  NOT NULL,
);

CREATE TABLE [Faculty] (
	[FacultyID] [int] PRIMARY KEY FOREIGN KEY REFERENCES [User](UserID) NOT NULL,
    [Name] [nvarchar](50) NOT NULL
);

CREATE TABLE [Student] (
	[StudentID] [int] PRIMARY KEY FOREIGN KEY REFERENCES [User](UserID) NOT NULL,
    [Name] [nvarchar](50) NOT NULL,
	[RollNumber] [varchar](10),
	[Image] [nvarchar](2083),
);

CREATE TABLE [Subject] (
	[SubjectID] [int] PRIMARY KEY IDENTITY(1,1),
	[Name] [nvarchar](50) NOT NULL,
	[Code] [varchar](10) NOT NULL,
	[Credit] [int] NOT NULL

);

CREATE TABLE [TimeTable] (
	[TimeTableID] [int] PRIMARY KEY IDENTITY(1,1),
	[Semester] [nvarchar](50) NOT NULL,
	[Slot] [varchar](50),
	[Date] [Datetime],
	[Room] [varchar](50),
	[Faculty] [int] FOREIGN KEY REFERENCES [Faculty](FacultyID),
	[SubjectID] [int] FOREIGN KEY REFERENCES [Subject](SubjectID),
	[StudentID] [int] FOREIGN KEY REFERENCES [Student](StudentID)
);



CREATE TABLE [Attendance] (
	[AttendanceID] [int] PRIMARY KEY IDENTITY(1,1),
	[Status] [bit],
	[StudentID] [int] FOREIGN KEY REFERENCES [Student](StudentID),
	[TimeTableID] [int] FOREIGN KEY REFERENCES [TimeTable](TimeTableID)
);

CREATE TABLE [Class] (
	[ClassID] [int] PRIMARY KEY IDENTITY(1,1),
	[Name] [nvarchar](50) NOT NULL,
	[Detail] [nvarchar](50),
	[SubjectID] [int] FOREIGN KEY REFERENCES [Subject](SubjectID)
);