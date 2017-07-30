import graphene
from graphene import relay
from graphene_sqlalchemy import SQLAlchemyObjectType, SQLAlchemyConnectionField
from models import db_session, trmst as TrmstModel, userid as UserIdModel, vpublokasi as VPubLokasiModel, vpubtrmst02 as VPubTrmst02Model, vpubtrdet04 as VPubTrdet04Model, vpubtrdet06 as VPubTrdet06Model, vbayardet02 as VBayarDet02Model

#schema = graphene.Schema()

class userid(SQLAlchemyObjectType):
    class Meta:
        model = UserIdModel
        interfaces = (relay.Node, )

class QueryType(graphene.ObjectType):

    name = 'Query'

    node = relay.Node.Field()
    #all_userid = SQLAlchemyConnectionField(userid)

#schema.query = Query

schema = graphene.Schema(
    query = QueryType
)