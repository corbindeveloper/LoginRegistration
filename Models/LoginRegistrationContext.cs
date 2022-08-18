#pragma warning disable CS8618
/* 
Disabled Warning: "Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable."
We can disable this safely because we know the framework will assign non-null values when it constructs this class for us.
*/
using Microsoft.EntityFrameworkCore;
namespace LoginRegistration.Models;
// the EFLectureContext class representing a session with our MySQL database, allowing us to query for or save data
public class LoginRegistrationContext : DbContext 
{ 
    public LoginRegistrationContext(DbContextOptions options) : base(options) { }
     
    
		// the "Posts" table name will come from the DbSet property name
    
		// public DbSet<Post> Posts { get; set; } !*!*

    public DbSet<User> Users { get; set; }
}