
using System.Collections.Generic;
using System.Threading.Tasks;
using API.DTOs;
using API.Entities;
using API.Extensions;
using API.Helpers;
using API.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Authorize]
  public class LikesController : BaseApiController
  {
    private readonly IUserRepository _userRespository;
    private readonly ILikesRepository _likeRepository;
    public LikesController(IUserRepository userRespository, ILikesRepository likeRepository)
    {
      _likeRepository = likeRepository;
      _userRespository = userRespository;
    }

    [HttpPost("{username}")]
    public async Task<ActionResult> AddLike(string username)
    {
        var sourceUserId  = User.GetUserId();
        var likedUser = await _userRespository.GetUserByUsernameAsync(username);
        var sourceUser = await _likeRepository.GetUserWithLikes(sourceUserId);

        if (likedUser == null) return NotFound();

        if(sourceUser.UserName == username) return BadRequest("You can not like yourself");

        var userLike =  await _likeRepository.GetUserLike(sourceUserId, likedUser.Id);

        if(userLike != null) return BadRequest("You already Liked this User");

        userLike = new UserLike
        {
            SourceUserId = sourceUserId,
            LikedUserId = likedUser.Id
        };

        sourceUser.LikedUsers.Add(userLike);

        if(await _userRespository.SaveAllAsync()) return Ok();

        return BadRequest("Failed to Like user");
    }

    [HttpGet]

    public async Task<ActionResult<IEnumerable<LikeDto>>> GetUserLikes([FromQuery]LikesParams likesParams)
    {
        likesParams.UserId =User.GetUserId();
        var users = await _likeRepository.GetUserLikes(likesParams);
        Response.AddPaginationHeader(users.CurrentPage, users.PageSize,users.TotalCount, users.TotalPages);
        return Ok(users);
    }
  }
}