﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MVCSecurityApp.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.Entity.Core.Objects;
    using System.Linq;
    
    public partial class AllSecurityDBEntities : DbContext
    {
        public AllSecurityDBEntities()
            : base("name=AllSecurityDBEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<AuditTB> AuditTBs { get; set; }
        public virtual DbSet<EmployeeDetail> EmployeeDetails { get; set; }
        public virtual DbSet<UserDetail> UserDetails { get; set; }
    
        public virtual ObjectResult<GetEmployeebyID_Result> GetEmployeebyID(Nullable<int> empID)
        {
            var empIDParameter = empID.HasValue ?
                new ObjectParameter("EmpID", empID) :
                new ObjectParameter("EmpID", typeof(int));
    
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<GetEmployeebyID_Result>("GetEmployeebyID", empIDParameter);
        }
    
        public virtual ObjectResult<GetEmployeebyIDandName_Result> GetEmployeebyIDandName(Nullable<int> empID)
        {
            var empIDParameter = empID.HasValue ?
                new ObjectParameter("EmpID", empID) :
                new ObjectParameter("EmpID", typeof(int));
    
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<GetEmployeebyIDandName_Result>("GetEmployeebyIDandName", empIDParameter);
        }
    
        public virtual int InsertEmployee(string name, string address, Nullable<int> age, Nullable<decimal> salary, string worktype)
        {
            var nameParameter = name != null ?
                new ObjectParameter("Name", name) :
                new ObjectParameter("Name", typeof(string));
    
            var addressParameter = address != null ?
                new ObjectParameter("Address", address) :
                new ObjectParameter("Address", typeof(string));
    
            var ageParameter = age.HasValue ?
                new ObjectParameter("Age", age) :
                new ObjectParameter("Age", typeof(int));
    
            var salaryParameter = salary.HasValue ?
                new ObjectParameter("Salary", salary) :
                new ObjectParameter("Salary", typeof(decimal));
    
            var worktypeParameter = worktype != null ?
                new ObjectParameter("worktype", worktype) :
                new ObjectParameter("worktype", typeof(string));
    
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction("InsertEmployee", nameParameter, addressParameter, ageParameter, salaryParameter, worktypeParameter);
        }
    }
}
