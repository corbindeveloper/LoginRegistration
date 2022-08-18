#pragma warning disable CS8618

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class User
{
    [Key]
    public int UserId { get; set; }


    [Required(ErrorMessage = "is required")]
    [MinLength(2, ErrorMessage = "Must be atleast two characters")]
    [Display(Name = "First Name")]
    public string FirstName { get; set; }


    [Required(ErrorMessage = "is required")]
    [MinLength(2, ErrorMessage = "Must be atleast two characters")]
    [Display(Name = "Last Name")]
    public string LastName { get; set; }

    
    [Required(ErrorMessage = "is required")]
    [EmailAddress]
    [Display(Name = "Email")]
    public string Email { get; set; }

    [Required(ErrorMessage = "is required")]
    [MinLength(8, ErrorMessage = "Must be atleast eight characters")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [NotMapped]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Doesn't match password.")]
    [Display(Name = "Confirm Password")]
    public string ConfirmPassword { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime UpdatedAt { get; set; } = DateTime.Now;


    public string FullName()
    {
        return FirstName + " " + LastName;
    }

}