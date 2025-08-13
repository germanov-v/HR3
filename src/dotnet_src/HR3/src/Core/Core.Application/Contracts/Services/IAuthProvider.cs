using Core.Application.Models.Identity;

namespace Core.Application.Contracts.Services;

public interface IAuthProvider
{
    public Task<ExternalIdentityResult> Authenticate();
}