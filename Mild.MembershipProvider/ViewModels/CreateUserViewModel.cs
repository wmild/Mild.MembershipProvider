using System;

namespace Mild.MembershipProvider.ViewModels
{
    public class CreateUserViewModel
    {
        public int Status { get; set; }
        public Guid UserId { get; set; }
        public DateTime Date { get; set; }
    }
}
