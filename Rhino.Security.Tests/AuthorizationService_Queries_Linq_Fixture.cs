using System.Linq;
using Remotion.Linq.Parsing.Structure.IntermediateModel;
using Rhino.Security.Impl.Util;
using Rhino.Security.Model;
using Xunit;

namespace Rhino.Security.Tests
{
    using NHibernate;
    using NHibernate.Criterion;

    public  class AuthorizationService_Queries_Linq_Fixture : DatabaseFixture
    {
        private IQueryable<Account> query;

        public AuthorizationService_Queries_Linq_Fixture()
        {
            query = session.Query<Account>();
        }

        [Fact]
        public void WillReturnNothingIfNoPermissionHasBeenDefined()
        {
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingIfNoPermissionHasBeenDefined_direct()
        {
            //authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            var operation = "/Account/Edit";

            string[] operationNames = Strings.GetHierarchicalOperationNames(operation);

            var f =
                (from a in query
                    join permission in session.Query<Permission>() 
                        on a.SecurityKey equals permission.EntitySecurityKey 
                    where operationNames.Contains(permission.Operation.Name) &&
                          permission.User == user
                    orderby permission.Level descending, permission.Allow
                    select new {permission.Allow, permission.EntitySecurityKey})
                .Take(1);
                
            
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfNoPermissionHasBeenDefined()
        {
            UsersGroup[] usersgroups = authorizationRepository.GetAssociatedUsersGroupFor(user);
            authorizationService.AddPermissionsToQuery(usersgroups[0], "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingIfOperationNotDefined()
        {
            authorizationService.AddPermissionsToQuery(user, "/Account/Delete", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfOperationNotDefined()
        {
            UsersGroup[] usersgroups = authorizationRepository.GetAssociatedUsersGroupFor(user);
            authorizationService.AddPermissionsToQuery(usersgroups[0], "/Account/Delete", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultIfAllowPermissionWasDefined()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .On(account)
                .DefaultLevel()
                .Save();

            session.Flush(); 
            
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupIfAllowPermissionWasDefined()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultIfAllowPermissionWasDefinedOnEverything()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupIfAllowPermissionWasDefinedOnEverything()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingIfAllowPermissionWasDefinedOnGroupAndDenyPermissionOnUser()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For("Administrators")
                .OnEverything()
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());

        }

        [Fact]
        public void WillReturnResultForUsersGroupIfAllowPermissionWasDefinedOnGroupAndDenyPermissionOnUser()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For("Administrators")
                .OnEverything()
                .DefaultLevel()
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());

        }


        [Fact]
        public void WillReturnNothingIfAllowedPermissionWasDefinedWithDenyPermissionWithHigherLevel()
        {            
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For("Administrators")
                .OnEverything()
                .Level(5)
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfAllowedPermissionWasDefinedWithDenyPermissionWithHigherLevel()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .DefaultLevel()
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .Level(5)
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultIfAllowedPermissionWasDefinedWithDenyPermissionWithLowerLevel()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .OnEverything()
                .Level(10)
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For("Administrators")
                .OnEverything()
                .Level(5)
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupIfAllowedPermissionWasDefinedWithDenyPermissionWithLowerLevel()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .Level(10)
                .Save();
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .Level(5)
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultOnAccountIfPermissionWasGrantedOnAnything()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupOnAccountIfPermissionWasGrantedOnAnything()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturNothingOnAccountIfPermissionWasDeniedOnAnything()
        {
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(user)
                .OnEverything()
                .DefaultLevel()
                .Save();
            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturNothingForUsersGroupOnAccountIfPermissionWasDeniedOnAnything()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(usersgroup)
                .OnEverything()
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultOnAccountIfPermissionWasGrantedOnGroupAssociatedWithUser()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For("Administrators")
                .On(account)
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupOnAccountIfPermissionWasGrantedOnGroup()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }


        [Fact]
        public void WillReturnNothingOnAccountIfPermissionWasDeniedOnGroupAssociatedWithUser()
        {
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For("Administrators")
                .On(account)
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupoOnAccountIfPermissionWasDeniedOnGroup()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(usersgroup)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultOnAccountIfPermissionWasGrantedToUser()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingOnAccountIfPermissionWasDeniedToUser()
        {
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(user)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultOnEntityGroupIfPermissionWasGrantedToUsersGroupAssociatedWithUser()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For("Administrators")
                .On("Important Accounts")
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupOnEntityGroupIfPermissionWasGrantedToUsersGroup()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .On("Important Accounts")
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingOnAccountIfPermissionWasDeniedToUserOnTheGroupTheEntityIsAssociatedWith()
        {
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(user)
                .On("Important Accounts")
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupOnAccountIfPermissionWasDeniedToUserOnTheGroupTheEntityIsAssociatedWith()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Deny("/Account/Edit")
                .For(usersgroup)
                .On("Important Accounts")
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultOnAccountIfPermissionWasAllowedToUserOnTheGroupTheEntityIsAssociatedWith()
        {
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .On("Important Accounts")
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnResultForUsersGroupOnAccountIfPermissionWasAllowedToUserOnTheGroupTheEntityIsAssociatedWith()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .On("Important Accounts")
                .DefaultLevel()
                .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingIfPermissionWasAllowedToChildGroupUserIsAssociatedWith()
        {
            authorizationRepository.CreateChildUserGroupOf("Administrators", "Helpdesk");
            

            permissionsBuilderService
               .Allow("/Account/Edit")
               .For("Helpdesk")
               .On("Important Accounts")
               .DefaultLevel()
               .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfPermissionWasAllowedToChildGroupOfVerifiedUsersGroup()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            authorizationRepository.CreateChildUserGroupOf("Administrators", "Helpdesk");
            

            permissionsBuilderService
               .Allow("/Account/Edit")
               .For("Helpdesk")
               .On("Important Accounts")
               .DefaultLevel()
               .Save();

            session.Flush();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnResultIfPermissionWasAllowedToParentGroupUserIsAssociatedWith()
        {
            authorizationRepository.CreateChildUserGroupOf("Administrators", "Helpdesk");
            

            authorizationRepository.DetachUserFromGroup(user, "Administrators");
            authorizationRepository.AssociateUserWith(user, "Helpdesk");
            

            permissionsBuilderService
               .Allow("/Account/Edit")
               .For("Administrators")
               .On("Important Accounts")
               .DefaultLevel()
               .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", query);
            Assert.NotEmpty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfPermissionWasAllowedToParentGroupOfVerifiedUsersGroup()
        {            
            authorizationRepository.CreateChildUserGroupOf("Administrators", "Helpdesk");
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Helpdesk");
            
            
            

            permissionsBuilderService
               .Allow("/Account/Edit")
               .For("Administrators")
               .On("Important Accounts")
               .DefaultLevel()
               .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", query);
            Assert.Empty(query.ToList());
        }

        [Fact]
        public void WillReturnNothingIfOperationNotDefined_WithDetachedCriteria()
        {
            DetachedCriteria detachedCriteria = DetachedCriteria.For<Account>();
            authorizationService.AddPermissionsToQuery(user, "/Account/Delete", detachedCriteria);
            Assert.Empty(detachedCriteria.GetExecutableCriteria(session).List());
        }

        [Fact]
        public void WillReturnNothingForUsersGroupIfOperationNotDefined_WithDetachedCriteria()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            DetachedCriteria detachedCriteria = DetachedCriteria.For<Account>();
            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Delete", detachedCriteria);
            Assert.Empty(detachedCriteria.GetExecutableCriteria(session).List());
        }

        [Fact]
        public void WillReturnResultIfAllowPermissionWasDefined_WithDetachedCriteria_AndConditions()
        {
            DetachedCriteria detachedCriteria = DetachedCriteria.For<Account>()
                .Add(Expression.Like("Name", "South",MatchMode.Start))
                ;
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(user)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(user, "/Account/Edit", detachedCriteria);
            Assert.NotEmpty(detachedCriteria.GetExecutableCriteria(session).List());
        }

        [Fact]
        public void WillReturnResultForUsersGroupIfAllowPermissionWasDefined_WithDetachedCriteria_AndConditions()
        {
            UsersGroup usersgroup = authorizationRepository.GetUsersGroupByName("Administrators");
            DetachedCriteria detachedCriteria = DetachedCriteria.For<Account>()
                .Add(Expression.Like("Name", "South", MatchMode.Start))
                ;
            permissionsBuilderService
                .Allow("/Account/Edit")
                .For(usersgroup)
                .On(account)
                .DefaultLevel()
                .Save();
            session.Flush();

            authorizationService.AddPermissionsToQuery(usersgroup, "/Account/Edit", detachedCriteria);
            Assert.NotEmpty(detachedCriteria.GetExecutableCriteria(session).List());
        }
    }
}
